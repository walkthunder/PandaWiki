#!/usr/bin/env python3
"""
测试腾讯云 COS 配置
"""
import os
from pathlib import Path

def load_cos_config():
    """加载 COS 配置"""
    config = {
        'secret_id': os.getenv('TENCENTCLOUD_SECRET_ID'),
        'secret_key': os.getenv('TENCENTCLOUD_SECRET_KEY'),
        'region': os.getenv('TENCENTCLOUD_COS_REGION'),
        'bucket': os.getenv('TENCENTCLOUD_COS_BUCKET')
    }
    
    # 如果环境变量不完整，尝试从 PandaWiki .env 文件读取
    if not all(config.values()):
        env_file = Path("/Users/penghuizheng/Projects/PandaWiki/.env")
        if env_file.exists():
            print("📖 从 PandaWiki .env 文件读取配置...")
            with open(env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        
                        if key == 'TENCENTCLOUD_SECRET_ID':
                            config['secret_id'] = value
                        elif key == 'TENCENTCLOUD_SECRET_KEY':
                            config['secret_key'] = value
                        elif key == 'TENCENTCLOUD_COS_REGION':
                            config['region'] = value
                        elif key == 'TENCENTCLOUD_COS_BUCKET':
                            config['bucket'] = value
    
    return config

def test_cos_connection(config):
    """测试 COS 连接"""
    try:
        from qcloud_cos import CosConfig, CosS3Client
        
        cos_config = CosConfig(
            Region=config['region'],
            SecretId=config['secret_id'],
            SecretKey=config['secret_key']
        )
        client = CosS3Client(cos_config)
        
        # 尝试列出存储桶中的对象（只列出1个）
        response = client.list_objects(
            Bucket=config['bucket'],
            MaxKeys=1
        )
        
        return True, "连接成功！"
    except Exception as e:
        return False, f"连接失败: {str(e)}"

def main():
    print("=" * 60)
    print("腾讯云 COS 配置测试")
    print("=" * 60)
    
    # 加载配置
    print("\n🔧 加载配置...")
    config = load_cos_config()
    
    # 检查配置完整性
    missing_keys = [k for k, v in config.items() if not v]
    if missing_keys:
        print(f"\n❌ 缺少配置项: {', '.join(missing_keys)}")
        print("\n请确保 PandaWiki .env 文件包含以下配置:")
        print("  - TENCENTCLOUD_SECRET_ID")
        print("  - TENCENTCLOUD_SECRET_KEY")
        print("  - TENCENTCLOUD_COS_REGION")
        print("  - TENCENTCLOUD_COS_BUCKET")
        return 1
    
    # 显示配置（隐藏敏感信息）
    print("\n✅ 配置加载成功:")
    print(f"   SecretId: {config['secret_id'][:8]}...{config['secret_id'][-4:]}")
    print(f"   SecretKey: {config['secret_key'][:8]}...{config['secret_key'][-4:]}")
    print(f"   区域: {config['region']}")
    print(f"   存储桶: {config['bucket']}")
    
    # 检查 SDK
    print("\n📦 检查 SDK...")
    try:
        import qcloud_cos
        print(f"   ✅ cos-python-sdk-v5 已安装")
    except ImportError:
        print("   ❌ cos-python-sdk-v5 未安装")
        print("\n请运行: pip3 install cos-python-sdk-v5")
        return 1
    
    # 测试连接
    print("\n🔌 测试 COS 连接...")
    success, message = test_cos_connection(config)
    
    if success:
        print(f"   ✅ {message}")
        print("\n🎉 所有测试通过！可以开始使用上传脚本。")
        return 0
    else:
        print(f"   ❌ {message}")
        print("\n请检查:")
        print("  1. SecretId 和 SecretKey 是否正确")
        print("  2. 存储桶名称是否正确")
        print("  3. 区域是否正确")
        print("  4. 网络连接是否正常")
        return 1

if __name__ == '__main__':
    import sys
    sys.exit(main())
