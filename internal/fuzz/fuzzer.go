package fuzz

import (
	core "Akemi/internal/core"
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func LazyReadPayloadsFromFile(filename string) (<-chan string, error) {
	payloadChan := make(chan string)

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}

	go func() {
		defer file.Close()
		defer close(payloadChan)

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			payloadChan <- scanner.Text()
		}

		if err := scanner.Err(); err != nil {
			log.Printf("Error reading file: %v", err)
		}
	}()

	return payloadChan, nil
}

func replaceFuzzMarker(input string, payload string) string {
	return strings.Replace(input, "FUZZ", payload, -1)
}

func saveResult(fileName string, url string, statusCode int, headers http.Header, payload string) {
	f, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	headersFormatted := ""
	for key, values := range headers {
		headersFormatted += fmt.Sprintf("%s: %s\n", key, strings.Join(values, ", "))
	}

	logEntry := fmt.Sprintf("URL: %s\nStatus Code: %d\nHeaders:\n%sPayload: %s\n%s\n",
		url, statusCode, headersFormatted, payload, strings.Repeat("+", 40))
	if _, err := f.WriteString(logEntry); err != nil {
		log.Fatal(err)
	}
}

func printTableHeader() {
	fmt.Printf("%-10s %-10s %-10s %-10s %-10s %-s\n", "ID", "Response", "Lines", "Words", "Chars", "Payload")
	fmt.Println(strings.Repeat("+", 60))
}

func printResult(id int, statusCode int, lines int, words int, chars int, payload string, mutex *sync.Mutex) {
	mutex.Lock()
	defer mutex.Unlock()
	fmt.Printf("%-10d %-10d %-10d %-10d %-10d %-s\n", id, statusCode, lines, words, chars, payload)
}

func analyzeResponseContent(content string) (lines int, words int, chars int) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	lines = 0
	words = 0
	chars = len(content)

	for scanner.Scan() {
		lines++
		lineWords := strings.Fields(scanner.Text())
		words += len(lineWords)
	}

	return lines, words, chars
}

func FuzzSingleRequest(
	client *http.Client,
	method string,
	target string,
	postData string,
	payload string,
	id int,
	fileName string,
	printMutex *sync.Mutex,
) core.FuzzResult {

	urlWithPayload := replaceFuzzMarker(target, payload)

	result := core.FuzzResult{
		ID:      id,
		URL:     urlWithPayload,
		Payload: payload,
	}

	var req *http.Request
	var err error

	if method == "GET" || method == "DELETE" {
		req, err = http.NewRequest(method, urlWithPayload, nil)
	} else {
		dataWithPayload := replaceFuzzMarker(postData, payload)
		data := strings.NewReader(dataWithPayload)
		req, err = http.NewRequest(method, urlWithPayload, data)
		if method == "POST" || method == "PUT" || method == "PATCH" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		result.Error = err.Error()
		return result
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error performing %s request: %v\n", method, err)
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	responseBody := string(body)

	lines, words, chars := analyzeResponseContent(responseBody)
	printResult(id, resp.StatusCode, lines, words, chars, payload, printMutex)
	saveResult(fileName, urlWithPayload, resp.StatusCode, resp.Header, payload)

	result.StatusCode = resp.StatusCode
	result.Lines = lines
	result.Words = words
	result.Chars = chars

	return result
}

func RunFuzzer(cfg core.FuzzConfig) ([]core.FuzzResult, time.Duration, error) {
	startTime := time.Now()

	payloadChan, err := LazyReadPayloadsFromFile(cfg.PayloadFile)
	if err != nil {
		return nil, 0, fmt.Errorf("error reading payloads: %w", err)
	}
	finalURL := core.EnsureProtocol(cfg.URL)
	method := strings.ToUpper(cfg.Method)
	client := core.CreateHTTPClient(cfg.Timeout)

	var wg sync.WaitGroup
	var printMutex sync.Mutex
	var resultsMutex sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)

	results := make([]core.FuzzResult, 0)

	printTableHeader()

	requestID := 1

	for payload := range payloadChan {
		for i := 0; i < cfg.Repeats; i++ {
			wg.Add(1)
			sem <- struct{}{}

			go func(payload string, id int) {
				defer func() { <-sem }()
				defer wg.Done()

				res := FuzzSingleRequest(client, method, finalURL, cfg.Data, payload, id, cfg.OutputFile, &printMutex)

				resultsMutex.Lock()
				results = append(results, res)
				resultsMutex.Unlock()
			}(payload, requestID)

			requestID++
		}
	}

	wg.Wait()
	elapsed := time.Since(startTime)
	return results, elapsed, nil
}
