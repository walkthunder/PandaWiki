"""
配置管理模块

提供配置加载、验证和管理功能。
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import argparse
import yaml
import os


@dataclass
class ConversionConfig:
    """转换配置"""
    input_dir: Path
    output_dir: Path
    recursive: bool = False
    max_workers: int = 4
    enable_ocr: bool = True
    enable_image_extraction: bool = True
    skip_existing: bool = False
    page_delimiter: str = "<||WXb23TXrUn3Rxz00yNNr89HV||>"
    
    def __post_init__(self):
        """初始化后处理，确保路径是 Path 对象"""
        if not isinstance(self.input_dir, Path):
            self.input_dir = Path(self.input_dir)
        if not isinstance(self.output_dir, Path):
            self.output_dir = Path(self.output_dir)
    
    @classmethod
    def from_yaml(cls, config_path: Path) -> 'ConversionConfig':
        """从 YAML 文件加载配置"""
        if not config_path.exists():
            raise FileNotFoundError(f"配置文件不存在: {config_path}")
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        
        return cls(
            input_dir=Path(config_data.get('input_dir', '.')),
            output_dir=Path(config_data.get('output_dir', 'outputs')),
            recursive=config_data.get('recursive', False),
            max_workers=config_data.get('max_workers', 4),
            enable_ocr=config_data.get('enable_ocr', True),
            enable_image_extraction=config_data.get('enable_image_extraction', True),
            skip_existing=config_data.get('skip_existing', False),
            page_delimiter=config_data.get('page_delimiter', "<||WXb23TXrUn3Rxz00yNNr89HV||>")
        )
    
    @classmethod
    def from_args(cls, args: argparse.Namespace) -> 'ConversionConfig':
        """从命令行参数创建配置"""
        # 如果指定了配置文件，先从配置文件加载
        if hasattr(args, 'config') and args.config:
            config = cls.from_yaml(Path(args.config))
            # 命令行参数覆盖配置文件
            if hasattr(args, 'input_dir') and args.input_dir:
                config.input_dir = Path(args.input_dir)
            if hasattr(args, 'output_dir') and args.output_dir:
                config.output_dir = Path(args.output_dir)
            if hasattr(args, 'recursive'):
                config.recursive = args.recursive
            if hasattr(args, 'max_workers') and args.max_workers:
                config.max_workers = args.max_workers
            if hasattr(args, 'no_ocr'):
                config.enable_ocr = not args.no_ocr
            if hasattr(args, 'no_images'):
                config.enable_image_extraction = not args.no_images
            if hasattr(args, 'skip_existing'):
                config.skip_existing = args.skip_existing
            return config
        
        # 否则从命令行参数创建新配置
        return cls(
            input_dir=Path(args.input_dir),
            output_dir=Path(args.output_dir) if args.output_dir else Path('outputs'),
            recursive=args.recursive if hasattr(args, 'recursive') else False,
            max_workers=args.max_workers if hasattr(args, 'max_workers') and args.max_workers else 4,
            enable_ocr=not args.no_ocr if hasattr(args, 'no_ocr') else True,
            enable_image_extraction=not args.no_images if hasattr(args, 'no_images') else True,
            skip_existing=args.skip_existing if hasattr(args, 'skip_existing') else False
        )
    
    def validate(self) -> tuple[bool, Optional[str]]:
        """
        验证配置的有效性
        
        Returns:
            (is_valid, error_message): 验证结果和错误消息
        """
        # 验证输入目录
        if not self.input_dir.exists():
            return False, f"输入目录不存在: {self.input_dir}"
        
        if not self.input_dir.is_dir():
            return False, f"输入路径不是目录: {self.input_dir}"
        
        if not os.access(self.input_dir, os.R_OK):
            return False, f"输入目录无读取权限: {self.input_dir}"
        
        # 验证 max_workers
        if self.max_workers < 1:
            return False, f"max_workers 必须大于 0，当前值: {self.max_workers}"
        
        if self.max_workers > 32:
            return False, f"max_workers 不应超过 32，当前值: {self.max_workers}"
        
        # 验证输出目录（如果存在）
        if self.output_dir.exists():
            if not self.output_dir.is_dir():
                return False, f"输出路径存在但不是目录: {self.output_dir}"
            
            if not os.access(self.output_dir, os.W_OK):
                return False, f"输出目录无写入权限: {self.output_dir}"
        
        return True, None
