const stripReferenceList = (content: string) => {
  const withoutHeading = content.replace(
    /\n?-{0,3}\s*\n*#{1,3}\s*引用列表[\s\S]*$/i,
    '',
  );
  if (withoutHeading !== content) {
    return withoutHeading.replace(/\n*-{3,}\s*$/, '').trimEnd();
  }
  // 流式输出时先出现分隔线，一并隐藏
  return content.replace(/\n+-{3,}\s*$/, '').trimEnd();
};

export const handleThinkingContent = (content: string) => {
  const thinkRegex = /<think>([\s\S]*?)(?:<\/think>|$)/g;
  const thinkMatches = [];
  let match;
  while ((match = thinkRegex.exec(content)) !== null) {
    thinkMatches.push(match[1]);
  }

  let answerContent = content.replace(/<think>[\s\S]*?<\/think>/g, '');
  answerContent = answerContent.replace(/<think>[\s\S]*$/, '');
  answerContent = stripReferenceList(answerContent);

  return {
    thinkingContent: thinkMatches.join(''),
    answerContent: answerContent,
  };
};
