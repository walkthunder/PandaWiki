package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"
)

type NodeReleaseVectorRequest struct {
	Action          string `json:"action"`
	NodeReleaseID   string `json:"node_release_id"`
	KBID           string `json:"kb_id"`
}

func main() {
	// 连接到NATS
	nc, err := nats.Connect("nats://panda-wiki:admin123@localhost:4222")
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	// 创建JetStream上下文
	js, err := nc.JetStream()
	if err != nil {
		log.Fatal(err)
	}

	// 要处理的文档
	docs := []NodeReleaseVectorRequest{
		{
			Action:        "upsert",
			NodeReleaseID: "861ded45-b2b1-4e41-9737-133495bbf191", // 常用无线电业务（一）
			KBID:         "860d7e13-a4f1-4103-ba86-59ff8c11b790",
		},
		{
			Action:        "upsert", 
			NodeReleaseID: "19bcf205-b0d9-4658-972b-1ef1a55258bd", // 常用无线电业务（三）
			KBID:         "860d7e13-a4f1-4103-ba86-59ff8c11b790",
		},
		{
			Action:        "upsert",
			NodeReleaseID: "3d4384ad-4fe2-4372-ae95-b8631c505c26", // 地面无线电台设置使用许可
			KBID:         "860d7e13-a4f1-4103-ba86-59ff8c11b790",
		},
	}

	// 发送消息到向量任务主题
	for _, doc := range docs {
		data, err := json.Marshal(doc)
		if err != nil {
			log.Printf("Failed to marshal doc %s: %v", doc.NodeReleaseID, err)
			continue
		}

		_, err = js.Publish("apps.panda-wiki.vector.task", data)
		if err != nil {
			log.Printf("Failed to publish doc %s: %v", doc.NodeReleaseID, err)
			continue
		}

		fmt.Printf("Triggered indexing for: %s\n", doc.NodeReleaseID)
		time.Sleep(100 * time.Millisecond) // 小延迟避免过快发送
	}

	fmt.Println("All documents triggered for indexing!")
}