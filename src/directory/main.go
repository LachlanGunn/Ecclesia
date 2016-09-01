package main

// FIXME: Check that SHA3_256 is linked in.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"runtime/pprof"
	"sort"
	"time"

	"protobufs"
	"shared/protocol_common"

	"github.com/Sirupsen/logrus"
	"github.com/gin-gonic/gin"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/ed25519"
)

var log = logrus.New()

type VerifierCommit struct {
	PublicKey            ed25519.PublicKey
	Address              string
	Time                 time.Time
	CommitValue          []byte
	DirectoryFingerprint []byte
	SignedValue          *protobufs.SignedMessage
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
	Commit VerifierCommit
	Reveal protobufs.VerifierReveal
}

type SignedValue struct {
	JSON      []byte
	Signature []byte
}

type Directory []*protobufs.DirectoryEntry

// Implement the sort interface for slice DirectoryEntry
func (slice Directory) Len() int {
	return len(slice)
}

func (slice Directory) Less(i, j int) bool {
	return bytes.Compare(
		slice[i].VerifierCommit.PublicKey,
		slice[j].VerifierCommit.PublicKey) < 0
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

	list.OwnerChannel <- 1

	return commit_cycle_times
}

func (list *VerifierRevealList) Add(reveal protobufs.VerifierReveal) {
	<-list.OwnerChannel
	list.Reveals[string(reveal.PublicKey)] = reveal
	list.OwnerChannel <- 1
}

// Determine whether or not we are in the reveal phase.
func reveal_ready(list *VerifierRevealList) bool {
	return (len(list.Ready) > 0)
}

func get_allowed_verifiers(filename string) map[string]bool {
	set := make(map[string]bool)
	fh, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Could not open verifier list %s.",
			filename)
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

	fh_secret, error := os.OpenFile(secret, os.O_RDONLY, 0600)
	if error != nil {
		log.Fatalf("Could not open %s", secret)
	}
	defer fh_secret.Close()

	secret_key_bytes, err := ioutil.ReadAll(fh_secret)
	if err != nil {
		log.Fatal(os.Stderr,
			"Could not read secret key from %s: %s",
			secret, err.Error())
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
	bind := flag.String("bind", ":8080", "<address>:<port> to bind to.")
	cycle := flag.Duration("cycle", time.Hour, "Commit/reveal cycle time.")
	secret := flag.String("key", "", "Secret key input file")
	directory_log_dir := flag.String("log", "directories/",
		"Output directory for verifier directories.")
	verifiers := flag.String("verifiers", "verifiers.conf",
		"public keys for permitted verifiers")
	cpuprofile := flag.String("cpuprofile", "", "Write cpu profile to file.")
	debug := flag.Bool("debug", false, "Set log level to 'debug'.")
	quiet := flag.Bool("quiet", false, "Only log errors.  Overrides 'debug'.")

	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatalf("Failed to open profiler output file %s: %s",
				*cpuprofile, err.Error())
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if *debug == true {
		log.Level = logrus.DebugLevel
	}

	if *quiet == true {
		log.Level = logrus.ErrorLevel
	}

	secret_key := get_keys(*secret)

	r := gin.New()
	r.Use(gin.Recovery())

	registration_queue := VerifierCommitList{
		make(map[string]VerifierCommit, 0),
		make(chan int, 1),
		make(chan VerifierCommit, 100)}
	registration_queue.OwnerChannel <- 1

	commits := VerifierCommitList{
		make(map[string]VerifierCommit, 0),
		make(chan int, 1),
		make(chan VerifierCommit, 100)}
	commits.OwnerChannel <- 1

	reveals := VerifierRevealList{
		make(map[string]protobufs.VerifierReveal, 0),
		make(chan int, 1),
		make(chan protobufs.VerifierReveal, 100),
		make(chan int, 1)}
	reveals.OwnerChannel <- 1

	allowed_verifiers := get_allowed_verifiers(*verifiers)
	cycle_times := CycleTimes{}
	var published_directory []byte
	var published_commits []byte

	r.POST("/verifier/commit", func(c *gin.Context) {
		add_verifier(
			c, &registration_queue,
			&allowed_verifiers, &cycle_times)
	})

	r.POST("/verifier/reveal", func(c *gin.Context) {
		add_reveal(c, &commits, &reveals, &allowed_verifiers)
	})

	r.GET("/verifier/list", func(c *gin.Context) {
		list_verifiers(c, &published_commits)
	})

	r.GET("/verifier/published", func(c *gin.Context) {
		c.Data(200, "application/json", published_directory)
	})

	go goroutine_reveal_list_append(&reveals)

	go goroutine_commit_reveal_publish_cycle(
		*cycle, &registration_queue, &commits, &reveals, &cycle_times,
		&published_commits, &published_directory,
		secret_key, *directory_log_dir)

	r.Run(*bind)
}

func check_verifier_allowed(public_key ed25519.PublicKey,
	allowed_verifiers *map[string]bool) bool {
	_, found := (*allowed_verifiers)[string(public_key)]
	return found
}

func add_verifier(c *gin.Context, list *VerifierCommitList,
	allowed_verifiers *map[string]bool,
	cycle_times *CycleTimes) {

	logging_context := logrus.Fields{
		"ClientIP": c.ClientIP()}

	encoded_data, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(500, gin.H{"result": "fail",
			"reason": "failed to read request"})
		logging_context["Error"] = err
		log.WithFields(logging_context).Error(
			"add_verifier: failed to read request body")
		return
	}

	signed_message, err := protocol_common.UnpackSignedData(
		encoded_data, func(key ed25519.PublicKey) bool {
			return true || check_verifier_allowed(
				key, allowed_verifiers)
		})
	if err != nil {
		c.JSON(400, gin.H{"result": "fail",
			"reason": err.Error()})
		logging_context["Error"] = err
		if log.Level >= logrus.DebugLevel {
			logging_context["EncodedDescriptor"] =
				base64.StdEncoding.EncodeToString(encoded_data)
		}
		log.WithFields(logging_context).Error(
			"add_verifier: failed to unpack signed blob")
		return
	}

	// Now we parse the commitment data.
	var raw_commit protobufs.VerifierCommit
	err = proto.Unmarshal(signed_message.Data, &raw_commit)
	if err != nil {
		c.JSON(400, gin.H{"result": "fail",
			"reason": "invalid commitment",
			"error":  err.Error(),
			"input":  signed_message.Data})
		logging_context["Error"] = err
		if log.Level >= logrus.DebugLevel {
			logging_context["SignedDescriptor"] = signed_message
		}
		log.WithFields(logging_context).Error(
			"add_verifier: failed to parse descriptor")
		return
	}

	logging_context["PublicKey"] = base64.StdEncoding.EncodeToString(
		raw_commit.PublicKey)
	logging_context["AdvertisedAddress"] = raw_commit.Address

	// Convert the protobuf structure to our internal type.
	// We need to parse the date first though.
	timestamp, err := time.Parse(time.RFC3339, raw_commit.Time)
	if err != nil {
		c.JSON(400, gin.H{"result": "fail",
			"reason": "time failed to parse"})
		logging_context["Error"] = err
		logging_context["BadTimestamp"] = raw_commit.Time
		log.WithFields(logging_context).Error(
			"add_verifier: failed to parse timestamp")
		return
	}
	verifier_data := VerifierCommit{
		PublicKey:            raw_commit.PublicKey,
		Address:              raw_commit.Address,
		Time:                 timestamp,
		CommitValue:          raw_commit.CommitValue,
		DirectoryFingerprint: raw_commit.DirectoryFingerprint,
		SignedValue:          signed_message}

	// Check whether the public key matches the one that we used
	// to verify the signature.
	if !bytes.Equal(verifier_data.PublicKey, signed_message.PublicKey) {
		c.JSON(403, gin.H{"result": "fail",
			"reason": "public keys in disagreement"})
		log.WithFields(logging_context).Error(
			"add_verifier: Non-matching public keys")
		return
	}

	// The verification done, we insert the new verifier into the list.
	commit_cycle_times := list.Add(verifier_data, cycle_times)

	// FIXME: Not thread-safe
	c.JSON(200, gin.H{
		"result":          "success",
		"DistributeWait":  -time.Since(commit_cycle_times.NextDistribution).Seconds(),
		"RevealWait":      -time.Since(commit_cycle_times.NextReveal).Seconds(),
		"PublicationWait": -time.Since(commit_cycle_times.NextPublication).Seconds()})

	log.WithFields(logging_context).Info(
		"add_verifier: Successful registration")
}

//
// HTTP request handler for the reveal process.
//
func add_reveal(
	c *gin.Context,
	commits *VerifierCommitList,
	reveals *VerifierRevealList,
	allowed_verifiers *map[string]bool) {

	logging_context := logrus.Fields{
		"ClientIP": c.ClientIP()}

	// First of all, check that we are within a reveal window.
	if !reveal_ready(reveals) {
		c.JSON(403, gin.H{"result": "fail",
			"reason": "outside of reveal window"})
		log.WithFields(logging_context).Error(
			"add_reveal: attempt to reveal outside of window")
		return
	}

	// Parse the ProtoBuf data into a reveal struct.
	reveal_data_json := c.PostForm("verifier_data")

	reveal := protobufs.VerifierReveal{}
	err := proto.Unmarshal([]byte(reveal_data_json), &reveal)
	if nil != err {
		c.JSON(400, gin.H{"result": "fail", "reason": "bad request"})
		log.WithFields(logging_context).Error(
			"add_reveal: invalid request")
		return
	}

	logging_context["PublicKey"] =
		base64.StdEncoding.EncodeToString(reveal.PublicKey)
	if log.Level >= logrus.DebugLevel {
		logging_context["RevealValue"] =
			base64.StdEncoding.EncodeToString(reveal.RevealValue)
	}

	// Next we check whether the verifier is (still) allowed to submit.
	if !check_verifier_allowed(reveal.PublicKey, allowed_verifiers) {
		c.JSON(403, gin.H{"result": "fail",
			"reason": "verifier not whitelisted"})
		log.WithFields(logging_context).Error(
			"add_reveal: authorisation failure")
		return
	}

	// Then we check that the verifier has indeed committed a value.
	<-commits.OwnerChannel

	commit, found := commits.Verifiers[string(reveal.PublicKey)]
	if !found {
		c.JSON(404, gin.H{
			"result": "fail",
			"reason": "no commitment registered"})
		log.WithFields(logging_context).Error(
			"add_reveal: No corresponding commitment")
		return
	}

	commits.OwnerChannel <- 1

	// Next check that the reveal matches the commit.  It is because
	// of this check that we don't need to authenticate.
	expected_commit_binary := sha256.Sum256(reveal.RevealValue)
	if !bytes.Equal(expected_commit_binary[:], commit.CommitValue) {
		c.JSON(403, gin.H{"result": "fail", "reason": "bad reveal"})
		log.WithFields(logging_context).Error(
			"add_reveal: Revealed data does not match commitment")
		return
	}

	reveals.InsertChannel <- reveal

	c.JSON(200, gin.H{"result": "success"})
	log.WithFields(logging_context).Info(
		"add_reveal: successful revelation")
}

func list_verifiers(c *gin.Context, list *[]byte) {
	c.Data(200, "application/octet-stream", *list)
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

		list.OwnerChannel <- 1
	}
}

//
// Produce a commit list for publication.
//
func generate_commit_list(list *VerifierCommitList) []byte {

	output_list := protobufs.VerifierCommitList{
		VerifierCommits: make(
			[]*protobufs.SignedMessage,
			len(list.Verifiers))}

	i := 0
	for _, k := range list.Verifiers {
		output_list.VerifierCommits[i] = k.SignedValue
		i++
	}

	encoded_list, err := proto.Marshal(&output_list)
	if err != nil {
		encoded_list, err =
			proto.Marshal(
				&protobufs.VerifierCommitList{
					[]*protobufs.SignedMessage{}})
		if err != nil {
			return []byte{}
		} else {
			return encoded_list
		}
	} else {
		return encoded_list
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
		reveal, found := verifier_reveal_list.Reveals[public_key]
		if found {
			directory[i] = &protobufs.DirectoryEntry{
				commit.SignedValue, reveal.RevealValue}
		}
		i++
	}

	old_fingerprint := sha256.Sum256(previous_directory)

	sort.Sort(directory)
	dir_timestamp := time.Now()
	result, err := proto.Marshal(&protobufs.Directory{
		dir_timestamp.Format(time.RFC3339),
		validity.String(),
		old_fingerprint[:],
		directory})

	if err != nil {
		return nil, dir_timestamp, err
	}

	signature := ed25519.Sign(secret_key, result)

	signed_directory, err := proto.Marshal(&protobufs.SignedMessage{
		[]byte(public_key), signature, result})

	return signed_directory, dir_timestamp, err
}

//
// Store a database log.
//
func store_directory(data []byte, timestamp time.Time, directory string) error {
	file_path := path.Join(directory, timestamp.Format(
		"2006-01-02T150405-0700")) + ".dir"
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
	cycle_time time.Duration,
	verifier_registration_queue *VerifierCommitList,
	verifier_commit_list *VerifierCommitList,
	verifier_reveal_list *VerifierRevealList,
	cycle_times *CycleTimes,
	published_commits *[]byte,
	published_directory *[]byte,
	secret_key ed25519.PrivateKey,
	output_directory string) {

	tick_channel := time.NewTicker(cycle_time).C
	public_key := secret_key.Public().(ed25519.PublicKey)

	// Each iteration is a one-hour cycle.
	for {
		// The commit-distribution phase.
		log.Info("Phase 1/2, commits outgoing")

		// Move the registration queue to the commit list.
		// We also need to update the cycle timestamps.
		<-verifier_registration_queue.OwnerChannel
		<-verifier_commit_list.OwnerChannel

		cycle_times.NextDistribution =
			time.Now().Add(2 * cycle_time)
		cycle_times.NextReveal =
			time.Now().Add(3 * cycle_time)
		cycle_times.NextPublication =
			time.Now().Add(4 * cycle_time)

		verifier_commit_list.Verifiers =
			verifier_registration_queue.Verifiers
		*published_commits = generate_commit_list(verifier_commit_list)

		verifier_commit_list.OwnerChannel <- 1

		verifier_registration_queue.Verifiers =
			make(map[string]VerifierCommit)

		verifier_registration_queue.OwnerChannel <- 1

		// The revelation phase.
		<-tick_channel
		log.Info("Phase 2/2, reveals incoming")

		// Empty the previous reveal list.
		<-verifier_reveal_list.OwnerChannel
		verifier_reveal_list.Reveals = make(map[string]protobufs.VerifierReveal)
		verifier_reveal_list.OwnerChannel <- 1

		// Indicate that we are ready to accept revelations.
		verifier_reveal_list.Ready <- 1

		// Publication of the commits.
		<-tick_channel

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

		directory_fingerprint := sha256.Sum256(*published_directory)
		log.WithFields(logrus.Fields{
			"Verifiers":   len(verifier_commit_list.Verifiers),
			"Reveals":     len(verifier_reveal_list.Reveals),
			"Fingerprint": hex.EncodeToString(directory_fingerprint[:]),
		}).Info("Published directory")
		store_directory(*published_directory, timestamp,
			output_directory)

		verifier_commit_list.OwnerChannel <- 1
		verifier_reveal_list.OwnerChannel <- 1
	}
}
