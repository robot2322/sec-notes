## 0x01 端口扫描

### 1.1 单个端口扫描

```
func PortConnect(host string, port int, timeout time.Duration){
	con, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%v", host, port),timeout)
	if err == nil{
		con.Close()
		result := fmt.Sprintf("%s:%s open", host, strconv.Itoa(port))
		fmt.Println(result)
	}
}

func main(){
	PortConnect("192.168.1.1", 80, 2 * time.Second)
}
```

### 1.2 并发端口扫描

```
func PortScan(host string, scanPorts []int, workers int, timeout float64) (aliveports []int, err error){

	ports := make(chan int, workers)
	results := make(chan int, workers)
	done := make(chan bool, workers)

	for i := 0; i < workers; i++{
		go PortConnect(host, ports, time.Duration(timeout)*time.Second, results, done)
	}

	for _, port := range scanPorts {
		ports <- port
	}
	close(ports)

	var responses = []int{}
	for {
		timeout := time.NewTimer(time.Second * 3)
		defer timeout.Stop()
		select {
		case found := <-results:
			responses = append(responses, found)
		case <-done:
			workers--
			if workers == 0 {
				return responses, nil
			}
		case <-timeout.C:
		}
	}

}

func PortConnect(host string, ports <-chan int, adjustedTimeout time.Duration, respondingPorts chan<- int, done chan<- bool){

	for port := range ports{
		start := time.Now()
		con, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%v", host, port),adjustedTimeout)
		duration := time.Now().Sub(start)
		if err == nil{
			con.Close()
			result := fmt.Sprintf("%s:%s open", host, strconv.Itoa(port))
			fmt.Println(result)
			respondingPorts <- port
		}
		if duration < adjustedTimeout {
			difference := adjustedTimeout - duration
			adjustedTimeout = adjustedTimeout - (difference / 2)
		}

	}

	done <- true

}

func main(){
	ports := [...]int{3389, 3391, 22 , 2222, 80, 443}
	PortScan("192.168.1.1", ports[:], 5, 2.5)
}
```

### 1.3 端口指纹识别

- 通过探针获取端口响应





## 0x02 漏洞扫描

### 2.1 主机漏洞扫描



### 2.2 Web漏洞扫描





