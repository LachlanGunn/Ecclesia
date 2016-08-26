package main

// FIXME: Check that SHA3_256 is linked in.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"time"

	"protobufs"
	"shared/protocol_common"

	"github.com/gin-gonic/gin"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/ed25519"
)

var _ = protobufs.VerifierCommit{}

type VerifierCommit struct {
	PublicKey   ed25519.PublicKey
	Address     string
	Time        time.Time
	CommitValue string
	JSON        []byte
	Signature   []byte
}

type VerifierReveal struct {
	PublicKey   ed25519.PublicKey
	RevealValue string
}

type VerifierCommitList struct {
	Verifiers     map[string]VerifierCommit
	OwnerChannel  chan int
	InsertChannel chan VerifierCommit
}

type VerifierRevealList struct {
	Reveals       map[string]protobufs.VerifierReveal
	OwnerChannel  chan int
	InsertChannel chan protobufs.VerifierReveal
	Ready         chan int
}

type CycleTimes struct {
	NextDistribution time.Time
	NextReveal       time.Time
	NextPublication  time.Time
}

type DirectoryEntry struct {
	Commit          VerifierCommit
	Reveal          protobufs.VerifierReveal
}

type SignedValue struct {
	JSON []byte
	Signature []byte
}

type Directory []DirectoryEntry

// Implement the sort interface for slice DirectoryEntry
func (slice Directory) Len() int {
	return len(slice)
}

func (slice Directory) Less(i, j int) bool {
	return bytes.Compare(
		slice[i].Commit.PublicKey, slice[j].Commit.PublicKey) < 0
}

func (slice Directory) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

// Implement append functionality for the commit and reveal lists.
func (list *VerifierCommitList) Add(commit VerifierCommit,
	                            cycle_times *CycleTimes) CycleTimes {
	<-list.OwnerChannel
	list.Verifiers[string(commit.PublicKey)] = commit
	
	// We make a copy of the cycle times since this needs to
	// be done atomically with list interactions.
	commit_cycle_times := *cycle_times
	
	list.OwnerChannel<- 1

	return commit_cycle_times
}

func (list *VerifierRevealList) Add(reveal protobufs.VerifierReveal) {
	<-list.OwnerChannel
	list.Reveals[string(reveal.PublicKey)] = reveal
	list.OwnerChannel<- 1	
}

// Implement JSON marshalling and unmarshalling for directory entries
func (entry *DirectoryEntry) MarshalJSON() ([]byte, error) {
	type Alias DirectoryEntry
	return json.Marshal(&struct {
		Commit    []byte
		Signature []byte
		Reveal    string
		*Alias
	}{
		Commit:    entry.Commit.JSON,
		Signature: entry.Commit.Signature,
		Reveal:    base64.StdEncoding.EncodeToString(entry.Reveal.RevealValue),
		Alias:    (*Alias)(entry),
	})
}

func (entry *DirectoryEntry) UnmarshalJSON(data []byte) error {
	type Alias DirectoryEntry
	aux := &struct {
		Commit    []byte
		Signature []byte
		Reveal    string
		*Alias
	}{
		Alias: (*Alias)(entry),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if err := json.Unmarshal(aux.Commit, &entry.Commit); err != nil {
		return err
	}

	entry.Commit.Signature = aux.Signature
	entry.Commit.JSON = aux.Commit

	reveal_value, err := base64.StdEncoding.DecodeString(aux.Reveal)
	if err != nil {
		return err
	}

	entry.Reveal = protobufs.VerifierReveal{entry.Commit.PublicKey, reveal_value}

	return nil
}

// Determine whether or not we are in the reveal phase.
func reveal_ready(list *VerifierRevealList) bool {
	return (len(list.Ready) > 0)
}

func get_allowed_verifiers(filename string) map[string]bool {
	set := make(map[string]bool)
	fh, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not open verifier list.\n")
		os.Exit(1)
	}

	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		key, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			message := fmt.Sprintf("Invalid public key %s\n",
				scanner.Text())
			panic(message)
		}

		set[string(key)] = true
	}

	fh.Close()
	return set
}

func get_keys(secret string) ed25519.PrivateKey {

	if secret == "" {
		fmt.Fprintf(os.Stderr,
			"USAGE: directory -cycle <duration> -key <file>\n")
		os.Exit(1)
	}

	fh_secret, error := os.OpenFile(secret, os.O_RDONLY|os.O_CREATE, 0600)
	if error != nil {
		fmt.Fprintf(os.Stderr, "Could not open %s\n", secret)
		os.Exit(1)
	}
	defer fh_secret.Close()

	secret_key_bytes, err := ioutil.ReadAll(fh_secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not read secret key.\n")
		os.Exit(1)
	}

	secret_key_bytes_decoded, err :=
		base64.StdEncoding.DecodeString(string(secret_key_bytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not decode secret key: %s\n",
			err.Error())
	}

	return ed25519.PrivateKey(secret_key_bytes_decoded)
}

func main() {
	cycle := flag.Duration("cycle", time.Hour, "Commit/reveal cycle time.")
	secret := flag.String("key", "", "Secret key input file")
	directory_log_dir := flag.String("log", "directories/",
		"Output directory for verifier directories.")

	flag.Parse()

	secret_key := get_keys(*secret)
	
	r := gin.Default()
	registration_queue := VerifierCommitList{
		make(map[string]VerifierCommit, 0),
		make(chan int, 1),
		make(chan VerifierCommit, 100)}
	registration_queue.OwnerChannel<- 1

	commits := VerifierCommitList{
		make(map[string]VerifierCommit, 0),
		make(chan int, 1),
		make(chan VerifierCommit, 100)}
	commits.OwnerChannel<- 1

	reveals := VerifierRevealList{
		make(map[string]protobufs.VerifierReveal, 0),
		make(chan int, 1),
		make(chan protobufs.VerifierReveal, 100),
		make(chan int, 1)}
	reveals.OwnerChannel<- 1
	
	allowed_verifiers := get_allowed_verifiers("verifiers.conf")
	cycle_times := CycleTimes{}
	var published_directory []byte

	
	r.POST("/verifier/commit", func(c *gin.Context) {
		add_verifier(
			c, &registration_queue,
			&allowed_verifiers, &cycle_times)
	})

	r.POST("/verifier/reveal", func(c *gin.Context) {
		add_reveal(c, &commits, &reveals, &allowed_verifiers)
	})

	r.GET("/verifier/list", func(c *gin.Context) {
		list_verifiers(c, &commits)
	})

	r.GET("/verifier/published", func(c *gin.Context) {
		c.Data(200, "application/json", published_directory)
	})

	go goroutine_reveal_list_append(&reveals)

	go goroutine_commit_reveal_publish_cycle(
		*cycle, &registration_queue, &commits, &reveals, &cycle_times,
		&published_directory, secret_key, *directory_log_dir)
	
	r.Run(":8080")
}

func check_verifier_allowed(public_key ed25519.PublicKey,
	                    allowed_verifiers *map[string]bool) bool {
	_, found := (*allowed_verifiers)[string(public_key)]
	return found
}

func add_verifier(c *gin.Context, list *VerifierCommitList,
	          allowed_verifiers *map[string]bool,
 	          cycle_times *CycleTimes) {

	encoded_data, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(500, gin.H{"result": "fail",
			"reason": "failed to read request"})
		return
	}

	signed_message, err := protocol_common.UnpackSignedData(
		encoded_data, func(key ed25519.PublicKey) bool {
			return check_verifier_allowed(
				key, allowed_verifiers)
		})
	if err != nil {
		c.JSON(400, gin.H{"result": "fail",
			"reason": err.Error()})
		return
	}
	
	// We need to parse the JSON data to make sure that the
	// public key has been signed.
	var verifier_data VerifierCommit
	err = json.Unmarshal(signed_message.Data, &verifier_data)
	if (err != nil) {
		fmt.Println(string(encoded_data))

		c.JSON(400, gin.H{"result": "fail",
			"reason": "invalid JSON",
			"error": err.Error(),
			"input": signed_message.Data})
		return
	}

	// Add the raw JSON and signature for later verification
	verifier_data.JSON = signed_message.Data
	verifier_data.Signature = signed_message.Signature

	// Check whether the public key matches the one that we used
	// to verify the signature.
	if !bytes.Equal(verifier_data.PublicKey, signed_message.PublicKey) {
		c.JSON(403, gin.H{"result": "fail",
			"reason": "public keys in disagreement"})
		return
	}

	// The verification done, we insert the new verifier into the list.	
	commit_cycle_times := list.Add(verifier_data, cycle_times)

	// FIXME: Not thread-safe
	c.JSON(200, gin.H{
		"result"         : "success",
		"DistributeWait" :
		    -time.Since(commit_cycle_times.NextDistribution).Seconds(),
		"RevealWait"     :
		    -time.Since(commit_cycle_times.NextReveal).Seconds(),
	        "PublicationWait":
		    -time.Since(commit_cycle_times.NextPublication).Seconds()})
}

//
// HTTP request handler for the reveal process.
//
func add_reveal(
	c       *gin.Context,
	commits *VerifierCommitList,
	reveals *VerifierRevealList,
	allowed_verifiers *map[string]bool) {

	// First of all, check that we are within a reveal window.
	if (!reveal_ready(reveals)) {
		c.JSON(403, gin.H{"result": "fail",
			"reason": "outside of reveal window"})
		return
	}

	// Parse the JSON data into a reveal struct.
	reveal_data_json := c.PostForm("verifier_data")

	reveal := protobufs.VerifierReveal{}
	err := proto.Unmarshal([]byte(reveal_data_json), &reveal)
	if (nil != err) {
		c.JSON(400, gin.H{"result": "fail", "reason": "bad json"})
		return
	}

	// Next we check whether the verifier is (still) allowed to submit.
	if !check_verifier_allowed(reveal.PublicKey, allowed_verifiers) {
		c.JSON(403, gin.H{"result": "fail",
			"reason": "verifier not whitelisted"})
		return
	}

	// Then we check that the verifier has indeed committed a value.
	<-commits.OwnerChannel

	commit, found := commits.Verifiers[string(reveal.PublicKey)]
	if !found {
		c.JSON(404, gin.H{
			"result": "fail",
			"reason": "no commitment registered"})
		return
	}
	
	commits.OwnerChannel<- 1

	// Next check that the reveal matches the commit.  It is because
	// of this check that we don't need to authenticate.
	//parsed_reveal, err :=
	//	base64.StdEncoding.DecodeString(reveal.RevealValue)
	//if nil != err {
	//	c.JSON(400, gin.H{"result": "fail", "reason": "bad reveal"})
	//	return
	//}

	// Now hash and check the revealed value
	expected_commit_binary := sha256.Sum256(reveal.RevealValue)// parsed_reveal)
	expected_commit_base64 :=
		base64.StdEncoding.EncodeToString(expected_commit_binary[:])
	if expected_commit_base64 != commit.CommitValue {
		c.JSON(403, gin.H{"result": "fail", "reason": "bad reveal"})
		return
	}

	reveals.InsertChannel <- reveal

	c.JSON(200, gin.H{"result": "success"})
}

func list_verifiers(c *gin.Context, list *VerifierCommitList) {
	<-list.OwnerChannel

	verifiers := make([]SignedValue, len(list.Verifiers))
	i := 0
	for _, k := range list.Verifiers {
		verifiers[i] = SignedValue{k.JSON, k.Signature}
		i++
	}
	c.JSON(200, verifiers)
	
	list.OwnerChannel<- 1
}

//
// Maintain the reveal list.  This accepts VerifierReveal structs via a
// channel (list.InsertChannel) and inserts them into a hashtable keyed
// by public key.
//
func goroutine_reveal_list_append(list *VerifierRevealList) {
	for {
		new_reveal := <-list.InsertChannel
		<-list.OwnerChannel

		list.Reveals[string(new_reveal.PublicKey)] = new_reveal
		
		list.OwnerChannel<- 1
	}
}

//
// Produce a verifier list for publication.
//
func generate_verifier_list(
	verifier_commit_list VerifierCommitList,
	verifier_reveal_list VerifierRevealList,
	public_key ed25519.PublicKey,
	secret_key ed25519.PrivateKey,
	previous_directory []byte,
	validity time.Duration) ([]byte, time.Time, error) {

	directory := make(Directory,
		len(verifier_reveal_list.Reveals))

	// Do essentially
	//
	// SELECT
	//   commits.*, reveals.*
	// FROM commits
	// LEFT JOIN reveals ON commits.PublicKey = reveals.PublicKey
	i := 0
	for public_key, _ := range verifier_reveal_list.Reveals {
		commit := verifier_commit_list.Verifiers[public_key]
		directory[i].Commit = commit
		reveal, found := verifier_reveal_list.Reveals[public_key]
		if found {
			directory[i].Reveal = reveal
		}
		i++
	}

	old_fingerprint := sha256.Sum256(previous_directory)

	sort.Sort(directory)
	dir_timestamp := time.Now()
	result, err := json.Marshal(struct{
		Verifiers     Directory
		LastDirectory string
		Time          time.Time
		Validity      time.Duration
	}{directory, hex.EncodeToString(old_fingerprint[:]), dir_timestamp,
		validity})

	if err != nil {
		return nil, dir_timestamp, err
	}

	signature := ed25519.Sign(secret_key, result)

	signed_directory, err := json.Marshal(struct{
		Directory []byte
		PublicKey []byte
		Signature []byte
	}{result, []byte(public_key), signature})

	return signed_directory, dir_timestamp, err
}

//
// Store a database log.
//
func store_directory(data []byte, timestamp time.Time, directory string) error {
	file_path := path.Join(directory, timestamp.Format(
		"2006-01-02T150405-0700")) + ".json"
	fmt.Println(file_path)
	fh, err := os.OpenFile(file_path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open file: %s\n", err.Error())
		return err
	}
	defer fh.Close()

	_, err = fh.Write(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write log: %s\n", err.Error())
	}
	return err
}

//
// Handle the commit-reveal-publish cycle.  This goroutine
// runs on a one-hour cycle with two thirty-minute phases.
//
//  /    Commit Distribution      |      Reveal submission      \
// |------------------------------|------------------------------|
// |                                \__________________________/ |
// |<-- Registration deadline                    |               |
//                                          Reveal period        |
//                                                               |
//                                      Directory publication -->|
//
// In the first phase, the list of verifier registrations
// is copied and made available to requesting parties.
// This allows them to ensure that each of the chosen values
// were indeed committed to beforehand.
//
// In the second phase, the verifiers reveal the values that they
// committed when they registered.
//
// After the second phase has completed, the directory computes
// the shared random value for the current hour along with the
// verifier list, which is then signed and distributed.
//
func goroutine_commit_reveal_publish_cycle(
	cycle_time                   time.Duration,
	verifier_registration_queue *VerifierCommitList,
	verifier_commit_list        *VerifierCommitList,
	verifier_reveal_list        *VerifierRevealList,
	cycle_times                 *CycleTimes,
	published_directory         *[]byte,
	secret_key                   ed25519.PrivateKey,
	output_directory             string) {

	tick_channel := time.NewTicker(cycle_time).C
	public_key   := secret_key.Public().(ed25519.PublicKey)

	// Each iteration is a one-hour cycle.
	for {
		// The commit-distribution phase.
		fmt.Println("Distributing committed values.")

		// Move the registration queue to the commit list.
		// We also need to update the cycle timestamps.
		<-verifier_registration_queue.OwnerChannel
		<-verifier_commit_list.OwnerChannel

		cycle_times.NextDistribution =
			time.Now().Add(2*cycle_time);
		cycle_times.NextReveal =
			time.Now().Add(3*cycle_time);
		cycle_times.NextPublication =
			time.Now().Add(4*cycle_time);


		verifier_commit_list.Verifiers =
			verifier_registration_queue.Verifiers

		verifier_commit_list.OwnerChannel <- 1

		verifier_registration_queue.Verifiers =
			make(map[string]VerifierCommit)

		verifier_registration_queue.OwnerChannel <- 1

		// The revelation phase.
		<-tick_channel
		fmt.Println("Accepting revealed values.")

		// Empty the previous reveal list.
		<-verifier_reveal_list.OwnerChannel
		verifier_reveal_list.Reveals = make(map[string]protobufs.VerifierReveal)
		verifier_reveal_list.OwnerChannel <- 1

		// Indicate that we are ready to accept revelations.
		verifier_reveal_list.Ready <- 1
		
		// Publication of the commits.
		<-tick_channel
		fmt.Println("Publishing directory.")

		// Indicate that the reveal window is over.
		// FIXME: Have we locked in the right order?
		<-verifier_reveal_list.Ready
		<-verifier_reveal_list.OwnerChannel
		<-verifier_commit_list.OwnerChannel

		var timestamp time.Time
		*published_directory, timestamp, _ = generate_verifier_list(
			*verifier_commit_list, *verifier_reveal_list,
			public_key, secret_key, *published_directory,
			4*cycle_time)

		store_directory(*published_directory, timestamp,
			output_directory)

		verifier_commit_list.OwnerChannel <- 1
		verifier_reveal_list.OwnerChannel <- 1
	}
}
