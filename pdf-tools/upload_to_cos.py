#!/usr/bin/env python3
"""
图片上传到腾讯云 COS 并更新 Markdown 链接脚本
功能：
1. 将 valid 目录中的图片上传到腾讯云 COS 的 wiki 目录
2. 更新 Markdown 文件中的图片链接
3. 生成上传报告
"""
import os
import re
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple
from qcloud_cos import CosConfig, CosS3Client
from tqdm import tqdm


class COSUploader:
    """腾讯云 COS 上传器"""
    
    def __init__(self, secret_id: str, secret_key: str, 
                 region: str, bucket: str, base_path: str = "wiki"):
        """
        初始化 COS 上传器
        
        Args:
            secret_id: 腾讯云 SecretId
            secret_key: 腾讯云 SecretKey
            region: COS 区域
            bucket: 存储桶名称
            base_path: 基础路径前缀
        """
        config = CosConfig(Region=region, SecretId=secret_id, SecretKey=secret_key)
        self.client = CosS3Client(config)
        self.bucket = bucket
        self.region = region
        self.base_path = base_path.strip('/')
        
        # 统计信息
        self.uploaded_count = 0
        self.skipped_count = 0
        self.failed_count = 0
        self.upload_mapping = {}  # 本地路径 -> COS URL
    
    def generate_cos_key(self, local_path: Path) -> str:
        """
        生成 COS 对象键
        
        Args:
            local_path: 本地文件路径
            
        Returns:
            COS 对象键
        """
        # 使用文件内容的 MD5 作为文件名，避免重复上传
        with open(local_path, 'rb') as f:
            content = f.read()
            md5_hash = hashlib.md5(content).hexdigest()
        
        # 保持原始扩展名
        ext = local_path.suffix
        filename = f"{md5_hash}{ext}"
        
        # 构建完整的 COS 键
        return f"{self.base_path}/images/{filename}"
    
    def object_exists(self, key: str) -> bool:
        """
        检查对象是否存在
        
        Args:
            key: COS 对象键
            
        Returns:
            是否存在
        """
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except:
            return False
    
    def upload_image(self, local_path: Path) -> Tuple[bool, str]:
        """
        上传单个图片到 COS
        
        Args:
            local_path: 本地图片路径
            
        Returns:
            (success, url_or_error): 成功标志和 URL 或错误信息
        """
        try:
            cos_key = self.generate_cos_key(local_path)
            
            # 检查文件是否已存在
            if self.object_exists(cos_key):
                self.skipped_count += 1
                # 构建 URL
                url = f"https://{self.bucket}.cos.{self.region}.myqcloud.com/{cos_key}"
                self.upload_mapping[str(local_path)] = url
                return True, url
            
            # 上传文件
            response = self.client.upload_file(
                Bucket=self.bucket,
                LocalFilePath=str(local_path),
                Key=cos_key
            )
            
            self.uploaded_count += 1
            # 构建 URL
            url = f"https://{self.bucket}.cos.{self.region}.myqcloud.com/{cos_key}"
            self.upload_mapping[str(local_path)] = url
            return True, url
                
        except Exception as e:
            self.failed_count += 1
            return False, f"上传异常: {str(e)}"
    
    def batch_upload(self, image_paths: List[Path]) -> Dict[str, str]:
        """
        批量上传图片
        
        Args:
            image_paths: 图片路径列表
            
        Returns:
            上传映射字典 {本地路径: COS URL}
        """
        print(f"🚀 开始上传 {len(image_paths)} 张图片到腾讯云 COS...")
        
        with tqdm(total=len(image_paths), desc="上传进度", unit="张") as pbar:
            for img_path in image_paths:
                success, result = self.upload_image(img_path)
                
                if success:
                    pbar.set_postfix_str(f"✅ {img_path.name}")
                else:
                    pbar.set_postfix_str(f"❌ {img_path.name}: {result}")
                
                pbar.update(1)
        
        return self.upload_mapping
    
    def get_stats(self) -> Dict:
        """获取上传统计信息"""
        return {
            'uploaded': self.uploaded_count,
            'skipped': self.skipped_count,
            'failed': self.failed_count,
            'total': self.uploaded_count + self.skipped_count + self.failed_count
        }


class MarkdownUpdater:
    """Markdown 文件更新器"""
    
    def __init__(self, valid_dir: Path):
        self.valid_dir = valid_dir
        self.updated_files = []
        self.update_count = 0
    
    def update_markdown_links(self, md_path: Path, url_mapping: Dict[str, str]) -> int:
        """
        更新单个 Markdown 文件中的图片链接
        
        Args:
            md_path: Markdown 文件路径
            url_mapping: 本地路径到 COS URL 的映射
            
        Returns:
            更新的链接数量
        """
        try:
            with open(md_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            updated_count = 0
            
            # 匹配 Markdown 图片语法: ![alt](image.png)
            def replace_image_link(match):
                nonlocal updated_count
                alt_text = match.group(1)
                image_name = match.group(2)
                
                # 查找对应的 COS URL
                local_image_path = str(self.valid_dir / image_name)
                if local_image_path in url_mapping:
                    updated_count += 1
                    return f"![{alt_text}]({url_mapping[local_image_path]})"
                else:
                    # 如果没找到对应的 COS URL，保持原样
                    return match.group(0)
            
            # 替换图片链接
            pattern = r'!\[(.*?)\]\(([^)]+\.png)\)'
            content = re.sub(pattern, replace_image_link, content)
            
            # 如果有更新，写回文件
            if content != original_content:
                with open(md_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.updated_files.append(md_path.name)
            
            return updated_count
            
        except Exception as e:
            print(f"警告: 更新 {md_path} 时出错: {e}")
            return 0
    
    def batch_update(self, url_mapping: Dict[str, str]) -> Dict:
        """
        批量更新 Markdown 文件
        
        Args:
            url_mapping: 本地路径到 COS URL 的映射
            
        Returns:
            更新统计信息
        """
        md_files = list(self.valid_dir.glob("*.md"))
        print(f"\n📝 更新 {len(md_files)} 个 Markdown 文件中的图片链接...")
        
        total_updates = 0
        
        with tqdm(total=len(md_files), desc="更新进度", unit="文件") as pbar:
            for md_file in md_files:
                updates = self.update_markdown_links(md_file, url_mapping)
                total_updates += updates
                
                if updates > 0:
                    pbar.set_postfix_str(f"✅ {md_file.name} ({updates} 个链接)")
                else:
                    pbar.set_postfix_str(f"⊘ {md_file.name}")
                
                pbar.update(1)
        
        self.update_count = total_updates
        
        return {
            'total_files': len(md_files),
            'updated_files': len(self.updated_files),
            'total_links': total_updates
        }


def load_cos_config() -> Dict[str, str]:
    """
    从环境变量或配置文件加载 COS 配置
    
    Returns:
        COS 配置字典
    """
    # 尝试从环境变量读取
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
                        
                        # 映射配置键
                        if key == 'TENCENTCLOUD_SECRET_ID':
                            config['secret_id'] = value
                        elif key == 'TENCENTCLOUD_SECRET_KEY':
                            config['secret_key'] = value
                        elif key == 'TENCENTCLOUD_COS_REGION':
                            config['region'] = value
                        elif key == 'TENCENTCLOUD_COS_BUCKET':
                            config['bucket'] = value
    
    # 验证配置完整性
    missing_keys = [k for k, v in config.items() if not v]
    if missing_keys:
        raise ValueError(f"缺少 COS 配置: {', '.join(missing_keys)}")
    
    return config


def generate_report(uploader: COSUploader, updater: MarkdownUpdater, 
                   output_path: Path) -> str:
    """
    生成上传和更新报告
    
    Args:
        uploader: COS 上传器
        updater: Markdown 更新器
        output_path: 报告输出路径
        
    Returns:
        报告内容
    """
    upload_stats = uploader.get_stats()
    
    report = []
    report.append("# 图片上传到腾讯云 COS 报告")
    report.append(f"\n生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # 上传统计
    report.append("## 📊 上传统计\n")
    report.append(f"- **总图片数**: {upload_stats['total']}")
    report.append(f"- **成功上传**: {upload_stats['uploaded']} ✅")
    report.append(f"- **跳过（已存在）**: {upload_stats['skipped']} ⊘")
    report.append(f"- **上传失败**: {upload_stats['failed']} ❌")
    
    # 更新统计
    report.append("\n## 📝 Markdown 更新统计\n")
    report.append(f"- **总 MD 文件数**: {updater.batch_update.__self__.update_count if hasattr(updater, 'batch_update') else 0}")
    report.append(f"- **更新的文件数**: {len(updater.updated_files)}")
    report.append(f"- **更新的链接数**: {updater.update_count}")
    
    # 更新的文件列表
    if updater.updated_files:
        report.append("\n## 📄 更新的文件列表\n")
        for i, filename in enumerate(sorted(updater.updated_files), 1):
            report.append(f"{i}. `{filename}`")
    
    # COS 配置信息
    report.append("\n## ⚙️ COS 配置\n")
    report.append(f"- **存储桶**: {uploader.bucket}")
    report.append(f"- **区域**: {uploader.region}")
    report.append(f"- **基础路径**: {uploader.base_path}")
    
    # 建议
    report.append("\n## 💡 建议\n")
    if upload_stats['failed'] > 0:
        report.append("- 检查失败的图片上传，可能需要重试")
    if upload_stats['uploaded'] > 0:
        report.append("- 图片已成功上传到 COS，Markdown 文件中的链接已更新")
    if len(updater.updated_files) > 0:
        report.append("- 可以删除本地图片文件，因为 Markdown 已使用 COS 链接")
    
    report_content = "\n".join(report)
    
    # 保存报告
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    return report_content


def main():
    """主函数"""
    print("=" * 60)
    print("图片上传到腾讯云 COS 工具")
    print("=" * 60)
    
    # 检查 valid 目录
    valid_dir = Path("outputs/valid")
    if not valid_dir.exists():
        print(f"❌ 错误: valid 目录不存在: {valid_dir}")
        print("请先运行 validate_outputs.sh 生成 valid 目录")
        return 1
    
    try:
        # 加载 COS 配置
        print("🔧 加载 COS 配置...")
        cos_config = load_cos_config()
        print(f"   存储桶: {cos_config['bucket']}")
        print(f"   区域: {cos_config['region']}")
        
        # 初始化上传器
        uploader = COSUploader(
            secret_id=cos_config['secret_id'],
            secret_key=cos_config['secret_key'],
            region=cos_config['region'],
            bucket=cos_config['bucket'],
            base_path="wiki"
        )
        
        # 扫描图片文件
        image_files = list(valid_dir.glob("*.png"))
        print(f"\n📷 发现 {len(image_files)} 张图片")
        
        if not image_files:
            print("⚠️  没有找到图片文件")
            return 0
        
        # 上传图片
        url_mapping = uploader.batch_upload(image_files)
        
        # 更新 Markdown 文件
        updater = MarkdownUpdater(valid_dir)
        update_stats = updater.batch_update(url_mapping)
        
        # 生成报告
        report_path = valid_dir / "cos_upload_report.md"
        report_content = generate_report(uploader, updater, report_path)
        
        # 显示结果
        print("\n" + "=" * 60)
        print(report_content)
        print("=" * 60)
        
        print(f"\n📊 报告已保存到: {report_path}")
        print("\n✅ 上传和更新完成！")
        
        upload_stats = uploader.get_stats()
        if upload_stats['failed'] > 0:
            return 1
        else:
            return 0
            
    except Exception as e:
        print(f"\n❌ 发生错误: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
