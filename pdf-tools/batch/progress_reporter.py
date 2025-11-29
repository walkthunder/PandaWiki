"""
进度报告模块

提供转换进度的实时反馈。
"""

from tqdm import tqdm
import time


class ProgressReporter:
    """进度报告器"""
    
    def __init__(self, total: int):
        """
        初始化进度报告器
        
        Args:
            total: 总文件数
        """
        self.total = total
        self.current = 0
        self.start_time = time.time()
        self.pbar = tqdm(
            total=total,
            desc="转换进度",
            unit="文件",
            bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]'
        )
    
    def update(self, current: int, filename: str, status: str):
        """
        更新进度
        
        Args:
            current: 当前已处理的文件数
            filename: 当前处理的文件名
            status: 处理状态（Success/Failed/Skipped）
        """
        # 计算增量
        increment = current - self.current
        self.current = current
        
        # 更新进度条
        if increment > 0:
            self.pbar.update(increment)
        
        # 设置状态信息
        status_icon = {
            "Success": "✓",
            "Failed": "✗",
            "Skipped": "⊘"
        }.get(status, "?")
        
        self.pbar.set_postfix_str(f"{status_icon} {filename}")
    
    def finish(self, elapsed_time: float):
        """
        完成并显示总结
        
        Args:
            elapsed_time: 总耗时（秒）
        """
        self.pbar.close()
        print(f"\n总耗时: {elapsed_time:.2f} 秒")
        
        if self.total > 0:
            avg_time = elapsed_time / self.total
            print(f"平均每个文件: {avg_time:.2f} 秒")
    
    def close(self):
        """关闭进度条"""
        if self.pbar:
            self.pbar.close()
