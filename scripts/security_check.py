#!/usr/bin/env python3
"""
生产环境文档安全检查脚本（Python版本）
提供更强大的内容分析和模式匹配功能
"""

import re
import sys
import json
import argparse
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, asdict


@dataclass
class SecurityIssue:
    """安全问题数据类"""
    severity: str  # high, medium, low
    category: str
    document_name: str
    kb_name: str
    issue_description: str
    matched_pattern: str = ""
    recommendation: str = ""


class SecurityChecker:
    """文档安全检查器"""
    
    # 敏感关键词模式定义
    PATTERNS = {
        'secret': {
            'keywords': ['密', '保密', '机密', '秘密', '绝密', '涉密', '内密'],
            'severity': 'medium',
            'description': '包含保密相关关键词'
        },
        'personal_info': {
            'keywords': ['通讯录', '花名册', '员工名单', '人员名单'],
            'severity': 'high',
            'description': '可能包含个人信息'
        },
        'financial': {
            'keywords': ['工资表', '薪资', '报价单', '预算表', '财务报表', '银行账号'],
            'severity': 'high',
            'description': '可能包含财务信息'
        },
        'internal': {
            'keywords': ['内部使用', '仅限内部', '草稿', '未定稿', '内部资料'],
            'severity': 'medium',
            'description': '标记为内部文档'
        },
        'contact': {
            'keywords': ['联系方式', '联系电话', '手机号'],
            'severity': 'low',
            'description': '包含联系方式'
        },
        'id_number': {
            'regex': r'\b\d{17}[\dXx]\b',  # 18位身份证号
            'severity': 'high',
            'description': '可能包含身份证号码'
        },
        'phone': {
            'regex': r'\b1[3-9]\d{9}\b',  # 11位手机号
            'severity': 'medium',
            'description': '包含手机号码'
        },
        'email': {
            'regex': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'severity': 'low',
            'description': '包含邮箱地址'
        }
    }
    
    def __init__(self, remote_host: str, remote_user: str, remote_port: int = 22):
        self.remote_host = remote_host
        self.remote_user = remote_user
        self.remote_port = remote_port
        self.issues: List[SecurityIssue] = []
        
    def execute_remote_sql(self, sql: str) -> str:
        """执行远程SQL查询"""
        cmd = [
            'ssh',
            f'{self.remote_user}@{self.remote_host}',
            f'docker exec panda-wiki-postgres psql -U panda-wiki -d panda-wiki -t -c "{sql}"'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"❌ SQL执行失败: {e.stderr}", file=sys.stderr)
            return ""
    
    def get_knowledge_bases(self) -> List[Dict]:
        """获取所有知识库"""
        sql = """
            SELECT id, name, access_settings::text 
            FROM knowledge_bases 
            ORDER BY created_at DESC;
        """
        
        result = self.execute_remote_sql(sql)
        kbs = []
        
        for line in result.split('\n'):
            if '|' in line:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 2:
                    kbs.append({
                        'id': parts[0],
                        'name': parts[1],
                        'access_settings': parts[2] if len(parts) > 2 else '{}'
                    })
        
        return kbs
    
    def get_documents(self, kb_id: Optional[str] = None) -> List[Dict]:
        """获取文档列表"""
        where_clause = f"AND n.kb_id = '{kb_id}'" if kb_id else ""
        
        sql = f"""
            SELECT 
                n.id,
                n.name,
                n.kb_id,
                kb.name as kb_name,
                n.type,
                n.created_at
            FROM nodes n
            JOIN knowledge_bases kb ON n.kb_id = kb.id
            WHERE n.type IN (2, 3) {where_clause}
            ORDER BY n.created_at DESC;
        """
        
        result = self.execute_remote_sql(sql)
        docs = []
        
        for line in result.split('\n'):
            if '|' in line:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 4:
                    docs.append({
                        'id': parts[0],
                        'name': parts[1],
                        'kb_id': parts[2],
                        'kb_name': parts[3],
                        'type': parts[4] if len(parts) > 4 else '',
                        'created_at': parts[5] if len(parts) > 5 else ''
                    })
        
        return docs
    
    def check_document_name(self, doc: Dict) -> None:
        """检查文档名称"""
        doc_name = doc['name']
        kb_name = doc['kb_name']
        
        # 检查关键词模式
        for pattern_name, pattern_config in self.PATTERNS.items():
            if 'keywords' in pattern_config:
                for keyword in pattern_config['keywords']:
                    if keyword in doc_name:
                        issue = SecurityIssue(
                            severity=pattern_config['severity'],
                            category=pattern_name,
                            document_name=doc_name,
                            kb_name=kb_name,
                            issue_description=pattern_config['description'],
                            matched_pattern=keyword,
                            recommendation=self._get_recommendation(pattern_name)
                        )
                        self.issues.append(issue)
                        break
        
        # 检查文件扩展名
        if doc_name.endswith(('.xls', '.xlsx')):
            issue = SecurityIssue(
                severity='medium',
                category='excel_file',
                document_name=doc_name,
                kb_name=kb_name,
                issue_description='Excel文件需要人工审查',
                matched_pattern='Excel文件',
                recommendation='下载文件并详细审查内容，确认是否包含敏感数据'
            )
            self.issues.append(issue)
    
    def check_document_content(self, doc: Dict) -> None:
        """检查文档内容（抽样检查）"""
        doc_id = doc['id']
        
        # 获取文档内容片段
        sql = f"""
            SELECT LEFT(content, 1000) as content_preview
            FROM nodes
            WHERE id = '{doc_id}';
        """
        
        content = self.execute_remote_sql(sql)
        
        if not content:
            return
        
        # 检查正则表达式模式
        for pattern_name, pattern_config in self.PATTERNS.items():
            if 'regex' in pattern_config:
                regex = pattern_config['regex']
                matches = re.findall(regex, content)
                
                if matches:
                    # 脱敏处理匹配结果
                    masked_matches = [self._mask_sensitive_data(m) for m in matches[:3]]
                    
                    issue = SecurityIssue(
                        severity=pattern_config['severity'],
                        category=pattern_name,
                        document_name=doc['name'],
                        kb_name=doc['kb_name'],
                        issue_description=pattern_config['description'],
                        matched_pattern=f"发现 {len(matches)} 处匹配: {', '.join(masked_matches)}",
                        recommendation=self._get_recommendation(pattern_name)
                    )
                    self.issues.append(issue)
    
    def _mask_sensitive_data(self, data: str) -> str:
        """脱敏处理敏感数据"""
        if len(data) <= 4:
            return '*' * len(data)
        return data[:2] + '*' * (len(data) - 4) + data[-2:]
    
    def _get_recommendation(self, pattern_name: str) -> str:
        """获取安全建议"""
        recommendations = {
            'secret': '确认是否为公开的法律法规文件，如果是内部涉密文件需立即删除',
            'personal_info': '立即审核文档内容，如包含真实个人信息需立即删除',
            'financial': '立即审核文档内容，如包含真实财务数据需立即删除',
            'internal': '确认文档是否适合对外公开，如不适合需删除或设置访问权限',
            'contact': '确认联系方式是否为公开信息（如政府部门公开电话）',
            'id_number': '立即审核并删除包含真实身份证号的文档',
            'phone': '确认手机号是否为公开信息，如为私人号码需删除',
            'email': '确认邮箱是否为公开联系邮箱',
            'excel_file': '下载并详细审查Excel文件内容'
        }
        return recommendations.get(pattern_name, '需要人工审核')
    
    def run_check(self, kb_id: Optional[str] = None, check_content: bool = False) -> None:
        """运行安全检查"""
        print(f"🔍 开始安全检查...")
        print(f"📡 连接服务器: {self.remote_host}")
        
        # 获取文档列表
        docs = self.get_documents(kb_id)
        print(f"📄 找到 {len(docs)} 个文档")
        
        # 检查文档名称
        print("🔎 检查文档名称...")
        for i, doc in enumerate(docs, 1):
            if i % 100 == 0:
                print(f"   已检查 {i}/{len(docs)} 个文档...")
            self.check_document_name(doc)
        
        # 检查文档内容（可选，较慢）
        if check_content:
            print("🔎 检查文档内容（抽样）...")
            sample_docs = docs[:50]  # 只检查前50个文档
            for i, doc in enumerate(sample_docs, 1):
                print(f"   检查内容 {i}/{len(sample_docs)}...")
                self.check_document_content(doc)
        
        print(f"✅ 检查完成，发现 {len(self.issues)} 个潜在问题")
    
    def generate_report(self, output_file: Path) -> None:
        """生成检查报告"""
        # 按严重程度分组
        high_issues = [i for i in self.issues if i.severity == 'high']
        medium_issues = [i for i in self.issues if i.severity == 'medium']
        low_issues = [i for i in self.issues if i.severity == 'low']
        
        # 生成Markdown报告
        report = f"""# 生产环境文档安全检查报告

**检查时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**服务器**: {self.remote_host}  
**发现问题数**: {len(self.issues)}

---

## 执行摘要

- 🔴 **高风险问题**: {len(high_issues)} 个
- 🟡 **中风险问题**: {len(medium_issues)} 个
- 🟢 **低风险问题**: {len(low_issues)} 个

---

## 高风险问题 (需立即处理)

"""
        
        if high_issues:
            for i, issue in enumerate(high_issues, 1):
                report += f"""
### {i}. {issue.document_name}

- **知识库**: {issue.kb_name}
- **问题类型**: {issue.issue_description}
- **匹配内容**: {issue.matched_pattern}
- **建议**: {issue.recommendation}

"""
        else:
            report += "✅ 未发现高风险问题\n\n"
        
        report += """---

## 中风险问题 (需要审核)

"""
        
        if medium_issues:
            for i, issue in enumerate(medium_issues, 1):
                report += f"""
### {i}. {issue.document_name}

- **知识库**: {issue.kb_name}
- **问题类型**: {issue.issue_description}
- **匹配内容**: {issue.matched_pattern}
- **建议**: {issue.recommendation}

"""
        else:
            report += "✅ 未发现中风险问题\n\n"
        
        report += """---

## 低风险问题 (建议关注)

"""
        
        if low_issues:
            # 低风险问题只列出前20个
            for i, issue in enumerate(low_issues[:20], 1):
                report += f"- **{issue.document_name}** ({issue.kb_name}): {issue.issue_description}\n"
            
            if len(low_issues) > 20:
                report += f"\n... 还有 {len(low_issues) - 20} 个低风险问题\n"
        else:
            report += "✅ 未发现低风险问题\n"
        
        report += f"""

---

## 安全建议

### 立即行动
1. 优先处理所有高风险问题
2. 审核中风险问题，确认是否需要删除或限制访问
3. 建立文档上传前的安全审核流程

### 长期措施
1. 定期运行此安全检查脚本（建议每周一次）
2. 制定文档分类和访问控制策略
3. 对上传者进行安全培训
4. 考虑实施自动化的敏感信息检测

---

**报告生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        # 写入文件
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(report, encoding='utf-8')
        print(f"📝 报告已保存到: {output_file}")
        
        # 同时生成JSON格式
        json_file = output_file.with_suffix('.json')
        json_data = {
            'check_time': datetime.now().isoformat(),
            'server': self.remote_host,
            'total_issues': len(self.issues),
            'high_risk': len(high_issues),
            'medium_risk': len(medium_issues),
            'low_risk': len(low_issues),
            'issues': [asdict(issue) for issue in self.issues]
        }
        json_file.write_text(json.dumps(json_data, ensure_ascii=False, indent=2), encoding='utf-8')
        print(f"📊 JSON数据已保存到: {json_file}")


def main():
    parser = argparse.ArgumentParser(
        description='生产环境文档安全检查工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --list                                    # 列出所有知识库
  %(prog)s --all                                     # 检查所有文档
  %(prog)s --kb 860d7e13-a4f1-4103-ba86-59ff8c11b790 # 检查指定知识库
  %(prog)s --all --check-content                     # 检查文档内容（较慢）
        """
    )
    
    parser.add_argument('--host', default='8.140.221.27', help='远程服务器地址')
    parser.add_argument('--user', default='root', help='远程服务器用户')
    parser.add_argument('--port', type=int, default=22, help='SSH端口')
    parser.add_argument('--list', action='store_true', help='列出所有知识库')
    parser.add_argument('--kb', help='指定要检查的知识库ID')
    parser.add_argument('--all', action='store_true', help='检查所有文档')
    parser.add_argument('--check-content', action='store_true', help='检查文档内容（较慢）')
    parser.add_argument('--output', default='./security-reports', help='输出目录')
    
    args = parser.parse_args()
    
    # 创建检查器
    checker = SecurityChecker(args.host, args.user, args.port)
    
    # 列出知识库
    if args.list:
        print("📚 知识库列表:")
        kbs = checker.get_knowledge_bases()
        for kb in kbs:
            print(f"  - {kb['name']} (ID: {kb['id']})")
        return
    
    # 运行检查
    if args.all or args.kb:
        checker.run_check(kb_id=args.kb, check_content=args.check_content)
        
        # 生成报告
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = Path(args.output) / f'security_check_{timestamp}.md'
        checker.generate_report(output_file)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
