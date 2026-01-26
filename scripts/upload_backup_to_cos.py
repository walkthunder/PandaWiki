#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PandaWiki 备份文件上传到腾讯云 COS
用途: 将备份文件上传到腾讯云对象存储
"""

import os
import sys
import argparse
from pathlib import Path
from qcloud_cos import CosConfig
from qcloud_cos import CosS3Client
from qcloud_cos.cos_exception import CosServiceError, CosClientError


class COSUploader:
    """腾讯云 COS 上传器"""
    
    def __init__(self, secret_id, secret_key, bucket, region):
        """初始化 COS 客户端"""
        self.bucket = bucket
        self.region = region
        
        # 配置 COS 客户端
        config = CosConfig(
            Region=region,
            SecretId=secret_id,
            SecretKey=secret_key,
            Scheme='https'
        )
        self.client = CosS3Client(config)
    
    def upload_file(self, local_file, cos_key, show_progress=True):
        """
        上传文件到 COS
        
        Args:
            local_file: 本地文件路径
            cos_key: COS 对象键（路径）
            show_progress: 是否显示进度
        
        Returns:
            bool: 上传是否成功
        """
        try:
            file_size = os.path.getsize(local_file)
            file_size_mb = file_size / (1024 * 1024)
            
            print(f"📤 开始上传: {os.path.basename(local_file)}")
            print(f"   文件大小: {file_size_mb:.2f} MB")
            print(f"   目标路径: cos://{self.bucket}/{cos_key}")
            
            # 根据文件大小选择上传方式
            if file_size_mb > 20:
                # 大文件使用分块上传
                print("   使用分块上传...")
                response = self.client.upload_file(
                    Bucket=self.bucket,
                    LocalFilePath=local_file,
                    Key=cos_key,
                    PartSize=1,  # 分块大小 1MB
                    MAXThread=3,  # 最大线程数
                    EnableMD5=False
                )
            else:
                # 小文件直接上传
                print("   使用简单上传...")
                with open(local_file, 'rb') as f:
                    response = self.client.put_object(
                        Bucket=self.bucket,
                        Body=f,
                        Key=cos_key,
                        EnableMD5=False
                    )
            
            # 检查上传结果
            if response:
                print(f"✅ 上传成功!")
                print(f"   ETag: {response.get('ETag', 'N/A')}")
                return True
            else:
                print(f"❌ 上传失败: 未知错误")
                return False
                
        except CosServiceError as e:
            print(f"❌ 上传失败 (服务端错误):")
            print(f"   错误码: {e.get_error_code()}")
            print(f"   错误信息: {e.get_error_msg()}")
            print(f"   请求ID: {e.get_request_id()}")
            return False
            
        except CosClientError as e:
            print(f"❌ 上传失败 (客户端错误):")
            print(f"   错误信息: {str(e)}")
            return False
            
        except Exception as e:
            print(f"❌ 上传失败 (未知错误):")
            print(f"   错误信息: {str(e)}")
            return False
    
    def check_file_exists(self, cos_key):
        """检查文件是否已存在"""
        try:
            self.client.head_object(
                Bucket=self.bucket,
                Key=cos_key
            )
            return True
        except:
            return False
    
    def list_backups(self, prefix):
        """列出指定前缀的备份文件"""
        try:
            response = self.client.list_objects(
                Bucket=self.bucket,
                Prefix=prefix,
                MaxKeys=100
            )
            
            if 'Contents' in response:
                return [obj['Key'] for obj in response['Contents']]
            return []
            
        except Exception as e:
            print(f"⚠️  列出备份文件失败: {str(e)}")
            return []


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description='上传 PandaWiki 备份文件到腾讯云 COS'
    )
    
    parser.add_argument(
        '--file',
        required=True,
        help='要上传的备份文件路径'
    )
    
    parser.add_argument(
        '--service',
        required=True,
        choices=['postgres', 'minio', 'qdrant'],
        help='服务类型'
    )
    
    parser.add_argument(
        '--date',
        required=True,
        help='备份日期 (YYYYMMDD)'
    )
    
    parser.add_argument(
        '--secret-id',
        required=True,
        help='腾讯云 SecretId'
    )
    
    parser.add_argument(
        '--secret-key',
        required=True,
        help='腾讯云 SecretKey'
    )
    
    parser.add_argument(
        '--bucket',
        required=True,
        help='COS Bucket 名称'
    )
    
    parser.add_argument(
        '--region',
        required=True,
        help='COS 区域'
    )
    
    parser.add_argument(
        '--prefix',
        default='panda-wiki-backups',
        help='COS 对象键前缀 (默认: panda-wiki-backups)'
    )
    
    return parser.parse_args()


def main():
    """主函数"""
    args = parse_args()
    
    # 检查文件是否存在
    if not os.path.exists(args.file):
        print(f"❌ 错误: 文件不存在: {args.file}")
        sys.exit(1)
    
    # 构建 COS 对象键
    filename = os.path.basename(args.file)
    cos_key = f"{args.prefix}/{args.date}/{args.service}/{filename}"
    
    # 创建上传器
    try:
        uploader = COSUploader(
            secret_id=args.secret_id,
            secret_key=args.secret_key,
            bucket=args.bucket,
            region=args.region
        )
    except Exception as e:
        print(f"❌ 初始化 COS 客户端失败: {str(e)}")
        sys.exit(1)
    
    # 检查文件是否已存在
    if uploader.check_file_exists(cos_key):
        print(f"⚠️  文件已存在: {cos_key}")
        print("   跳过上传")
        sys.exit(0)
    
    # 上传文件
    success = uploader.upload_file(args.file, cos_key)
    
    if success:
        print(f"\n🎉 备份上传完成!")
        print(f"   访问路径: https://{args.bucket}.cos.{args.region}.myqcloud.com/{cos_key}")
        sys.exit(0)
    else:
        print(f"\n❌ 备份上传失败!")
        sys.exit(1)


if __name__ == '__main__':
    main()
