#!/usr/bin/env python3
"""
输出文件验证和整理脚本

功能：
1. 检查 MD 文件是否有实际内容
2. 验证图片链接的有效性
3. 将有效文件移动到 valid/ 目录
4. 将无效文件移动到 invalid/ 目录
5. 生成详细报告
"""

import os
import re
import shutil
from pathlib import Path
from datetime import datetime
from collections import defaultdict


class OutputValidator:
    """输出文件验证器"""
    
    def __init__(self, output_dir: str = "outputs"):
        self.output_dir = Path(output_dir)
        self.valid_dir = self.output_dir / "valid"
        self.invalid_dir = self.output_dir / "invalid"
        
        # 统计数据
        self.stats = {
            'total_md': 0,
            'valid_md': 0,
            'invalid_md': 0,
            'total_images': 0,
            'valid_images': 0,
            'orphan_images': 0,
            'empty_md': 0,
            'no_content_md': 0
        }
        
        # 文件映射
        self.valid_files = []
        self.invalid_files = []
        self.image_usage = defaultdict(list)  # 图片 -> 使用它的 MD 文件列表
        
    def is_md_valid(self, md_path: Path) -> tuple[bool, str]:
        """
        检查 MD 文件是否有效
        
        Returns:
            (is_valid, reason)
        """
        try:
            with open(md_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 检查文件是否为空
            if not content.strip():
                return False, "文件为空"
            
            # 检查是否只有很少的内容（少于 100 字符）
            if len(content.strip()) < 100:
                return False, f"内容过少（{len(content.strip())} 字符）"
            
            # 检查是否有实际内容（不只是标题和分隔符）
            # 移除常见的无意义内容
            cleaned = content
            cleaned = re.sub(r'#+\s*\n', '', cleaned)  # 移除空标题
            cleaned = re.sub(r'-{3,}', '', cleaned)    # 移除分隔线
            cleaned = re.sub(r'={3,}', '', cleaned)    # 移除分隔线
            cleaned = re.sub(r'\s+', ' ', cleaned)     # 压缩空白
            cleaned = cleaned.strip()
            
            if len(cleaned) < 50:
                return False, f"实际内容过少（{len(cleaned)} 字符）"
            
            return True, "有效"
            
        except Exception as e:
            return False, f"读取错误: {e}"
    
    def extract_image_references(self, md_path: Path) -> list[str]:
        """提取 MD 文件中引用的图片"""
        try:
            with open(md_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 匹配 Markdown 图片语法: ![alt](image.png)
            pattern = r'!\[.*?\]\(([^)]+\.png)\)'
            matches = re.findall(pattern, content)
            
            return matches
            
        except Exception as e:
            print(f"警告: 无法读取 {md_path}: {e}")
            return []
    
    def scan_files(self):
        """扫描输出目录中的所有文件"""
        print("🔍 扫描输出目录...")
        
        # 扫描所有 MD 文件
        md_files = list(self.output_dir.glob("*.md"))
        self.stats['total_md'] = len(md_files)
        
        print(f"   发现 {len(md_files)} 个 MD 文件")
        
        for md_file in md_files:
            # 跳过报告文件
            if md_file.name in ['conversion_report.txt', 'error_report.txt', 'validation_report.md']:
                continue
            
            # 检查 MD 文件有效性
            is_valid, reason = self.is_md_valid(md_file)
            
            if is_valid:
                self.stats['valid_md'] += 1
                self.valid_files.append({
                    'type': 'md',
                    'path': md_file,
                    'reason': reason
                })
                
                # 提取图片引用
                images = self.extract_image_references(md_file)
                for img in images:
                    # 图片路径可能是相对的，需要解析
                    img_path = md_file.parent / img
                    if img_path.exists():
                        self.image_usage[str(img_path)].append(md_file.name)
            else:
                self.stats['invalid_md'] += 1
                self.invalid_files.append({
                    'type': 'md',
                    'path': md_file,
                    'reason': reason
                })
                
                if "为空" in reason:
                    self.stats['empty_md'] += 1
                else:
                    self.stats['no_content_md'] += 1
        
        # 扫描所有图片文件
        image_files = list(self.output_dir.glob("*.png"))
        self.stats['total_images'] = len(image_files)
        
        print(f"   发现 {len(image_files)} 个图片文件")
        
        for img_file in image_files:
            if str(img_file) in self.image_usage:
                self.stats['valid_images'] += 1
                self.valid_files.append({
                    'type': 'image',
                    'path': img_file,
                    'used_by': self.image_usage[str(img_file)]
                })
            else:
                self.stats['orphan_images'] += 1
                self.invalid_files.append({
                    'type': 'image',
                    'path': img_file,
                    'reason': '未被任何 MD 文件引用'
                })
    
    def organize_files(self):
        """整理文件到对应目录"""
        print("\n📁 整理文件...")
        
        # 创建目录
        self.valid_dir.mkdir(exist_ok=True)
        self.invalid_dir.mkdir(exist_ok=True)
        
        # 移动有效文件
        print(f"   移动 {len([f for f in self.valid_files if f['type'] == 'md'])} 个有效 MD 文件...")
        for file_info in self.valid_files:
            if file_info['type'] == 'md':
                src = file_info['path']
                dst = self.valid_dir / src.name
                shutil.copy2(src, dst)
        
        print(f"   移动 {len([f for f in self.valid_files if f['type'] == 'image'])} 个有效图片...")
        for file_info in self.valid_files:
            if file_info['type'] == 'image':
                src = file_info['path']
                dst = self.valid_dir / src.name
                shutil.copy2(src, dst)
        
        # 移动无效文件
        print(f"   移动 {len([f for f in self.invalid_files if f['type'] == 'md'])} 个无效 MD 文件...")
        for file_info in self.invalid_files:
            if file_info['type'] == 'md':
                src = file_info['path']
                dst = self.invalid_dir / src.name
                shutil.copy2(src, dst)
        
        print(f"   移动 {len([f for f in self.invalid_files if f['type'] == 'image'])} 个孤立图片...")
        for file_info in self.invalid_files:
            if file_info['type'] == 'image':
                src = file_info['path']
                dst = self.invalid_dir / src.name
                shutil.copy2(src, dst)
    
    def generate_report(self) -> str:
        """生成验证报告"""
        report = []
        report.append("# PDF 转 Markdown 验证报告")
        report.append(f"\n生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # 总体统计
        report.append("## 📊 总体统计\n")
        report.append(f"- **总 MD 文件数**: {self.stats['total_md']}")
        report.append(f"- **有效 MD 文件**: {self.stats['valid_md']} ✅")
        report.append(f"- **无效 MD 文件**: {self.stats['invalid_md']} ❌")
        report.append(f"  - 空文件: {self.stats['empty_md']}")
        report.append(f"  - 内容过少: {self.stats['no_content_md']}")
        report.append(f"- **总图片数**: {self.stats['total_images']}")
        report.append(f"- **有效图片**: {self.stats['valid_images']} ✅")
        report.append(f"- **孤立图片**: {self.stats['orphan_images']} ⚠️")
        
        # 成功率
        if self.stats['total_md'] > 0:
            success_rate = (self.stats['valid_md'] / self.stats['total_md']) * 100
            report.append(f"\n**转换成功率**: {success_rate:.1f}%")
        
        # 有效文件列表
        report.append("\n## ✅ 有效文件列表\n")
        valid_md_files = [f for f in self.valid_files if f['type'] == 'md']
        
        if valid_md_files:
            report.append(f"共 {len(valid_md_files)} 个有效 MD 文件：\n")
            for i, file_info in enumerate(sorted(valid_md_files, key=lambda x: x['path'].name), 1):
                report.append(f"{i}. `{file_info['path'].name}`")
                
                # 显示关联的图片数量
                images = [f for f in self.valid_files 
                         if f['type'] == 'image' and file_info['path'].name in f.get('used_by', [])]
                if images:
                    report.append(f"   - 包含 {len(images)} 张图片")
        else:
            report.append("*没有有效的 MD 文件*")
        
        # 无效文件列表
        report.append("\n## ❌ 无效文件列表\n")
        invalid_md_files = [f for f in self.invalid_files if f['type'] == 'md']
        
        if invalid_md_files:
            report.append(f"共 {len(invalid_md_files)} 个无效 MD 文件：\n")
            for i, file_info in enumerate(sorted(invalid_md_files, key=lambda x: x['path'].name), 1):
                report.append(f"{i}. `{file_info['path'].name}` - {file_info['reason']}")
        else:
            report.append("*没有无效的 MD 文件*")
        
        # 孤立图片
        if self.stats['orphan_images'] > 0:
            report.append(f"\n## ⚠️ 孤立图片（未被引用）\n")
            report.append(f"共 {self.stats['orphan_images']} 个孤立图片")
        
        # PDF 对应关系
        report.append("\n## 📄 PDF 转换对应关系\n")
        if valid_md_files:
            report.append("| PDF 文件名 | Markdown 文件 | 状态 |")
            report.append("|-----------|--------------|------|")
            for file_info in sorted(valid_md_files, key=lambda x: x['path'].name):
                md_name = file_info['path'].name
                pdf_name = md_name.replace('.md', '.pdf')
                report.append(f"| {pdf_name} | {md_name} | ✅ 成功 |")
        
        # 文件位置说明
        report.append("\n## 📁 文件组织\n")
        report.append(f"- **有效文件**: `{self.valid_dir}/`")
        report.append(f"  - {self.stats['valid_md']} 个 MD 文件")
        report.append(f"  - {self.stats['valid_images']} 个图片文件")
        report.append(f"- **无效文件**: `{self.invalid_dir}/`")
        report.append(f"  - {self.stats['invalid_md']} 个 MD 文件")
        report.append(f"  - {self.stats['orphan_images']} 个图片文件")
        
        # 建议
        report.append("\n## 💡 建议\n")
        if self.stats['invalid_md'] > 0:
            report.append("- 检查无效的 MD 文件，可能需要重新转换对应的 PDF")
        if self.stats['orphan_images'] > 0:
            report.append("- 孤立图片可以安全删除，它们未被任何 MD 文件使用")
        if self.stats['valid_md'] == self.stats['total_md']:
            report.append("- 🎉 所有 MD 文件都是有效的！")
        
        return "\n".join(report)
    
    def save_report(self, report: str):
        """保存报告到文件"""
        report_path = self.output_dir / "validation_report.md"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"\n📊 报告已保存到: {report_path}")
    
    def run(self):
        """运行完整的验证和整理流程"""
        print("=" * 60)
        print("PDF 转 Markdown 输出验证和整理工具")
        print("=" * 60)
        
        # 检查输出目录是否存在
        if not self.output_dir.exists():
            print(f"❌ 错误: 输出目录不存在: {self.output_dir}")
            return
        
        # 扫描文件
        self.scan_files()
        
        # 整理文件
        self.organize_files()
        
        # 生成报告
        report = self.generate_report()
        
        # 显示报告
        print("\n" + "=" * 60)
        print(report)
        print("=" * 60)
        
        # 保存报告
        self.save_report(report)
        
        print("\n✅ 验证和整理完成！")
        print(f"   - 有效文件: {self.valid_dir}/")
        print(f"   - 无效文件: {self.invalid_dir}/")
        print(f"   - 详细报告: {self.output_dir}/validation_report.md")


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='验证和整理 PDF 转 Markdown 的输出文件'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default='outputs',
        help='输出目录路径（默认: outputs）'
    )
    
    args = parser.parse_args()
    
    validator = OutputValidator(args.output_dir)
    validator.run()


if __name__ == '__main__':
    main()
