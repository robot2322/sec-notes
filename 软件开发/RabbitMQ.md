## 0x01 工作队列

### 1.1 轮转分发

#### 1.1.1 简介

​	默认情况下，RabbitMQ会将队列中的每条消息平均分发给每个消费者，一个队列中的同一条消息不会同时发送给超过2个消费者，这种分发消息的方式就是"轮转分发"。

#### 1.1.2 实现

- 生产者

```
package main

import (
    "fmt"
    "log"
    "os"
    "strings"

    "github.com/streadway/amqp"
)

func failOnError(err error, msg string) {
    if err != nil {
        log.Fatalf("%s: %s", msg, err)
        panic(fmt.Sprintf("%s: %s", msg, err))
    }
}

func main() {
    //连接服务器
    conn, err := amqp.Dial("amqp://guest:guest@192.168.1.100:5672/")
    failOnError(err, "Failed to connect to RabbitMQ")
    defer conn.Close()

    //声明channel
    ch, err := conn.Channel()
    failOnError(err, "Failed to open a channel")
    defer ch.Close()

    //声明队列
    q, err := ch.QueueDeclare(
        "hello", // 队列名称        
        false,   // 是否持久化
        false,   // 是否自动删除
        false,   // 是否独立
        false,   // no-wait
        nil,     // arguments
    )
    failOnError(err, "Failed to declare a queue")

    //创建请求体
    body := "Hello World!"
    //发送消息
    err = ch.Publish(
        "",     // exchange     交换器名称，使用默认
        q.Name, // routing key    路由键，这里为队列名称
        false,  // mandatory
        false,
        amqp.Publishing{
        	DeliveryMode: amqp.Persistent, // 消息标记为持久
            ContentType:  "text/plain",    // 消息类型，文本消息
            Body:         []byte(body),
        })
    failOnError(err, "Failed to publish a message")
    log.Printf(" [x] Sent %s", body)
}
```

- 消费者

```
package main

import (
    "bytes"
    "fmt"
    "log"
    "time"

    "github.com/streadway/amqp"
)

func failOnError(err error, msg string) {
    if err != nil {
        log.Fatalf("%s: %s", msg, err)
        panic(fmt.Sprintf("%s: %s", msg, err))
    }
}

func main() {
    //链接服务器
    conn, err := amqp.Dial("amqp://guest:guest@192.168.1.100:5672/")
    failOnError(err, "Failed to connect to RabbitMQ")
    defer conn.Close()

    //声明channel
    ch, err := conn.Channel()
    failOnError(err, "Failed to open a channel")
    defer ch.Close()

    //声明队列
    q, err := ch.QueueDeclare(
        "hello", // name    队列名称
        false,   // durable    持久化标识
        false,   // autoDelete	是否自动删除
        false,   // exclusive	是否独立
        false,   // no-wait	
        nil,     // arguments
    )
    failOnError(err, "Failed to declare a queue")

    //声明消费者
    msgs, err := ch.Consume(
        q.Name, // queue    消费的队列名称
        "",     // consumer
        true,   // auto-ack 自动应答默认为true，设置为false关闭
        false,  // exclusive
        false,  // no-local
        false,  // no-wait
        nil,    // args
    )
    failOnError(err, "Failed to register a consumer")

    forever := make(chan bool) //主要用来防止主进程窗口退出

    go func() {
        for d := range msgs {
            log.Printf("Received a message: %s", d.Body)
            dot_count := bytes.Count(d.Body, []byte("."))
            t := time.Duration(dot_count)
            time.Sleep(t * time.Second) //延时x秒
            log.Printf("Done")
            //d.Ack(false) //消息应答
        }
    }()

    log.Printf(" [*] Waiting for messages. To exit press CTRL+C")
    <-forever
}
```

### 1.2 公平调度

#### 1.2.1 简介

​	公平调度是指RabbitMQ在同一时间不要发送超过一条消息给每个消费者，也就是说直到消息被处理和应答之前都不会发送给该消费者任何消息，而是发送消息给下一个比较闲的消费者。

#### 1.2.2 实现

- 消费者

```
package main

import (
    "bytes"
    "fmt"
    "log"
    "time"

    "github.com/streadway/amqp"
)

func failOnError(err error, msg string) {
    if err != nil {
        log.Fatalf("%s: %s", msg, err)
        panic(fmt.Sprintf("%s: %s", msg, err))
    }
}

func main() {
    //链接服务器
    conn, err := amqp.Dial("amqp://guest:guest@192.168.1.100:5672/")
    failOnError(err, "Failed to connect to RabbitMQ")
    defer conn.Close()

    //声明channel
    ch, err := conn.Channel()
    failOnError(err, "Failed to open a channel")
    defer ch.Close()

    //声明队列
    q, err := ch.QueueDeclare(
        "hello", // name    队列名称
        false,   // durable    持久化标识
        false,   // autoDelete	是否自动删除
        false,   // exclusive	是否独立
        false,   // no-wait	
        nil,     // arguments
    )
    failOnError(err, "Failed to declare a queue")
    
    // 公平调度
    err = ch.Qos(
        1,     // prefetch count
        0,     // prefetch size
        false, // global
    )
    failOnError(err, "Failed to set QoS")

    //声明消费者
    msgs, err := ch.Consume(
        q.Name, // queue    消费的队列名称
        "",     // consumer
        true,   // auto-ack 自动应答默认为true，设置为false关闭
        false,  // exclusive
        false,  // no-local
        false,  // no-wait
        nil,    // args
    )
    failOnError(err, "Failed to register a consumer")

    forever := make(chan bool) //主要用来防止主进程窗口退出

    go func() {
        for d := range msgs {
            log.Printf("Received a message: %s", d.Body)
            dot_count := bytes.Count(d.Body, []byte("."))
            t := time.Duration(dot_count)
            time.Sleep(t * time.Second) //延时x秒
            log.Printf("Done")
            //d.Ack(false) //消息应答
        }
    }()

    log.Printf(" [*] Waiting for messages. To exit press CTRL+C")
    <-forever
}
```

## 0x02 发布订阅

### 2.1 交换器

#### 2.1.1 简介

​	交换器一边从生产者那边接受消息一边发送这些消息至队列，交换器必须准确定义这些被接受的消息该如何处理。交换器类型有四种：direct、topic、headers、fanout，fanout是一种广播类型，可以广播所有消息到已知队列中。

#### 2.1.2 实现

- 生产者/消费者

```
//声明一个交换器，交换器名称log，类型fanout
err = ch.ExchangeDeclare(
	"log",
	"fanout",
	true,
	false,
	false,
	false,
	nil,
)
failOnError(err, "Failed to declare an exchange")
```

### 2.2 临时队列

#### 2.2.1 简介

​	每当连接RabbitMQ时创建一个名称随机的临时队列，一旦消费者断开连接，该队列便会自动删除。

#### 2.2.2 实现

- 消费者

```
// 声明一个临时队列
q,err := ch.QueueDeclare(
	"", // 队列名称为空，服务端自动产生随机队列
	false,   // 是否持久化
	false,   // 是否自动删除
	true,   // 是否独立，连接断开立即删除
	false,   // no-wait
	nil,     // arguments
)
failOnError(err, "Failed to declare a queue")

// 绑定交换器和临时队列
err = ch.QueueBind(
	q.Name, // queue name    绑定的队列名称
	"",     // routing key    绑定的路由键
	"log", // exchange    绑定的交换器名称
	false,
	nil,
)
```

### 2.3 广播消息

#### 2.3.1 简介

​	通过交换器和临时队列实现广播消息

#### 2.3.2 实现

- 生产者

```
package main

import (
	"log"

	"github.com/streadway/amqp"
)

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func main(){

	// 连接RabbitMQ服务器
	conn, err := amqp.Dial("amqp://guest:guest@192.168.1.100:5672/")
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	// 创建一个channel
	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	//声明一个交换器，交换器名称log，类型fanout
	err = ch.ExchangeDeclare(
		"log",
		"fanout",
		true,
		false,
		false,
		false,
		nil,
	)
	failOnError(err, "Failed to declare an exchange")

	// 发送消息到交换器
	body := "Hello World!"
	err = ch.Publish(
		"log",     // 交换
		"", // 路由建
		false,  // mandatory
		false,  // 立即
		amqp.Publishing {
			//DeliveryMode: amqp.Persistent,
			ContentType: "text/plain",
			Body:        []byte(body),
		})
	failOnError(err, "Failed to publish a message")
}
```

- 消费者

```
package main

import (
	"log"

	"github.com/streadway/amqp"
)

// 检查mq的返回值
func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func main(){

	// 连接RabbitMQ服务器
	conn, err := amqp.Dial("amqp://guest:guest@192.168.1.100:5672/")
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	// 声明一个交换器，交换器名称log，类型fanout
	err = ch.ExchangeDeclare(
		"log",
		"fanout",
		true,
		false,
		false,
		false,
		nil,
		)

	failOnError(err, "failed to declare the exchange")

	// 声明一个队列
	q, err := ch.QueueDeclare(
		"", // name
		false,   // durable
		false,   // delete when unused
		true,   // exclusive
		false,   // no-wait
		nil,     // arguments
	)
	failOnError(err, "Failed to declare a queue")

	// 设置绑定
	err = ch.QueueBind(
		q.Name,
		"",
		"log",
		false,
		nil,
	)

	failOnError(err, "failed to bind the queue")

	/*
	err = ch.Qos(
		1,     // prefetch count
		0,     // prefetch size
		false, // global
	)
	failOnError(err, "Failed to set QoS")
	 */

	// 注册一个消费队列
	msgs, err := ch.Consume(
		q.Name, // queue
		"",     // consumer
		true,   // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)
	failOnError(err, "Failed to register a consumer")

	// 创建一个协程始终监听消费队列
	forever := make(chan bool)

	go func() {
		for d := range msgs {
			log.Printf("Received a message: %s", d.Body)
		}
	}()

	log.Printf(" [*] Waiting for messages. To exit press CTRL+C")
	<-forever

}
```

