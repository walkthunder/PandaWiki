#!/usr/bin/env python3

import json
import asyncio
import nats
import sys

async def trigger_document_indexing():
    # 连接到NATS
    nc = await nats.connect("nats://panda-wiki:admin123@localhost:4222")
    js = nc.jetstream()
    
    # 获取一些无线电相关的文档ID
    node_releases = [
        {
            "kb_id": "860d7e13-a4f1-4103-ba86-59ff8c11b790",
            "node_release_id": "9ae3e49f-8bad-444b-a937-b844edf316fb",  # 中国无线电
            "action": "upsert"
        },
        {
            "kb_id": "860d7e13-a4f1-4103-ba86-59ff8c11b790", 
            "node_release_id": "c85bd4bd-db88-4bcb-a09e-cd1dda9298cc",  # 无线电台执照管理规定
            "action": "upsert"
        },
        {
            "kb_id": "860d7e13-a4f1-4103-ba86-59ff8c11b790",
            "node_release_id": "1179a5d9-403a-4315-af3b-65ab69bba2cd",  # 业余无线电台管理办法
            "action": "upsert"
        }
    ]
    
    # 发送消息到向量任务主题
    for doc in node_releases:
        message = json.dumps(doc).encode()
        await js.publish("apps.panda-wiki.vector.task", message)
        print(f"Triggered indexing for: {doc['node_release_id']}")
    
    await nc.close()
    print("All documents triggered for indexing!")

if __name__ == "__main__":
    asyncio.run(trigger_document_indexing())