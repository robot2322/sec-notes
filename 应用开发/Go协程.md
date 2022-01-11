## 0x01、简介

### 1.1 Goroutine

​	Goroutine是一种特殊的函数，能够创建用户态线程，并且共享相同的地址空间。Goroutine由用户进行调度和控制，操作系统并不知道Goroutine的存在。

### 1.2 进程、线程和协程

​	进程是系统进行资源分配和调度的基本单位，是程序的执行实体，每一个程序执行后都生成自己的地址空间，其中包括代码区域、数据区域、堆栈。

​	线程是程序的最小执行单元，一个进程可以包括多个线程。

​	协程是应用层模拟的线程，系统并不知道协程的存在，由用户自己进行调度控制。

## 0x02、协程的应用

### 2.1 创建协程

​	使用go做为前缀的函数即为协程函数，会启动一个goroutine在后台执行。

```
go func()
```

### 2.2 WaitGroup

​	sync包的WaitGroup类型用于等待程序协程执行完毕。

```
package main

import (
	"fmt"
	"sync"
)

// 创建waitGroup变量
var wg sync.WaitGroup

func Add(x, y int) {
	// 调用waitGroup的done函数使计数器-1
	defer wg.Done()
    z := x + y
    fmt.Println(z)
}
 
func main() {
    for i:=0; i<10; i++ {
    	// 添加计数
    	wg.Add(1)
        go Add(i, i)
    }
    // 等待goroutine执行完毕
    wg.Wait()
}
```

### 2.3 协程传值

​	channel是连接并发协程的管道，通过channel可以将值从一个goroutine传到另外一个goroutine中。

```
package main

import (
	"fmt"
	"sync"
)

var wg sync.WaitGroup

func Add(x int, num chan int) {
	defer wg.Done()
    z := x + 100
    // 传递值到无缓存channel
    num <- z
}
 
func main() {
	num := make(chan int)
	wg.Add(1)
	go Add(10, num)
	// 输出channel中的值
	fmt.Println(<-num)
    wg.Wait()
	close(num)
}
```

### 2.4 协程控制

​	使用Channel充当管道来暂停和继续执行Goroutine的执行。

```
package main

import (
	"fmt"
	"sync"
	"time"
)

var i int

func work() {
	time.Sleep(1000 * time.Millisecond)
	i++
	fmt.Println(i)
}

func routine(command <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	var status = "开始"
	for {
		select {
		case cmd := <-command:
			fmt.Println(cmd)
			switch cmd {
			case "Stop":
				status = "停止"
				return
			case "Pause":
				status = "暂停"
			case "Start":
				status = "开始"
			}
		default:
			if status == "开始" {
				work()
			}

		}
	}
}

func main() {
	var wg sync.WaitGroup
	wg.Add(1)
	command := make(chan string)
	go routine(command, &wg)

	time.Sleep(5 * time.Second)
	command <- "Pause"

	time.Sleep(5 * time.Second)
	command <- "Start"

	time.Sleep(5 * time.Second)
	command <- "Stop"

	wg.Wait()
}
```

## 0x03、并发安全

### 3.1 条件竞争

​	如果一个请求刚刚完成账户余额的检查，余额不为0，而另外一个请求检查账户余额也不为0，那这两次转账操作同时进行会导致转账成功，余额为负值。

```
package main

import (
	"fmt"
	"net/http"
	"time"
)

type User struct {
	Cash int
}

func (u *User) sendCash(to *User, amount int) bool {
	if u.Cash < amount {
		return false
	}
	/* 设置延迟Sleep，当多个goroutines并行执行时,便于进行数据安全分析 */
	time.Sleep(500 * time.Millisecond)
	u.Cash = u.Cash - amount
	to.Cash = to.Cash + amount
	return true
}

func main() {
	me := User{Cash: 500}
	you := User{Cash: 500}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		me.sendCash(&you, 50) //转账
		fmt.Fprintf(w, "I have $%d\n", me.Cash)
		fmt.Fprintf(w, "You have $%d\n", you.Cash)
		fmt.Fprintf(w, "Total transferred: $%d\n", (you.Cash - 500))
	})
	http.ListenAndServe(":8080", nil)
}
```

### 3.2 漏洞修复

​	通过委托一个后台协程监听通道，当通道中有数据时，立即进行转账操作，因为协程是顺序读取通道中的数据，也就避免了竞争情况。

```
package main

import (
	"fmt"
	"net/http"
	"time"
)

type User struct {
	Cash int
}

type Transfer struct {
	Sender *User
	Recipient *User
	Amount int
}

func sendCashHandler(transferchan chan Transfer) {
	var val Transfer
	for {
		val = <-transferchan
		val.Sender.sendCash(val.Recipient, val.Amount)
	}
}

func (u *User) sendCash(to *User, amount int) bool {
	if u.Cash < amount {
		return false
	}
	/* 设置延迟Sleep，当多个goroutines并行执行时,便于进行数据安全分析 */
	time.Sleep(500 * time.Millisecond)
	u.Cash = u.Cash - amount
	to.Cash = to.Cash + amount
	return true
}

func main() {
	me := User{Cash: 500}
	you := User{Cash: 500}
	transferchan := make(chan Transfer)
	go sendCashHandler(transferchan)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		transfer := Transfer{Sender: &me, Recipient: &you, Amount: 50}
		/*转账*/
		result := make(chan int)
		go func(transferchan chan<- Transfer, transfer Transfer, result chan<- int) {
			transferchan <- transfer
			result <- 1
		}(transferchan, transfer, result)

		/*用select来处理超时机制*/
		select {
		case <-result:
			fmt.Fprintf(w, "I have $%d\n", me.Cash)
			fmt.Fprintf(w, "You have $%d\n", you.Cash)
			fmt.Fprintf(w, "Total transferred: $%d\n", (you.Cash - 500))
		case <-time.After(time.Second * 10): //超时处理
			fmt.Fprintf(w, "Your request has been received, but is processing slowly")
		}
	})
	http.ListenAndServe(":8080", nil)
}
```
