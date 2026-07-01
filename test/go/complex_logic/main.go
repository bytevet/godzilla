package main

import (
	"fmt"
	"sync"
)

type Processor interface {
	Process(data string) string
}

type MyProcessor struct{}

func (p *MyProcessor) Process(data string) string {
	return "Processed: " + data
}

func main() {
	// Channels and Concurrency
	ch := make(chan int, 2)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ch <- 1
		ch <- 2
		close(ch)
	}()

	// Select and Range
	for i := range ch {
		select {
		case v := <-ch:
			fmt.Println("Received:", v)
		default:
			fmt.Println("No more data", i)
		}
	}

	// Maps and Slices
	m := make(map[string]int)
	m["key"] = 10
	val, ok := m["key"]
	if ok {
		fmt.Println("Map value:", val)
	}

	s := make([]string, 0, 5)
	s = append(s, "hello")
	fmt.Println("Slice:", s)

	// Interfaces and Type Assertions
	var p Processor = &MyProcessor{}
	if mp, ok := p.(*MyProcessor); ok {
		fmt.Println(mp.Process("input"))
	}

	// Panic and Defer
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from:", r)
		}
	}()
	// panic("test panic")
}
