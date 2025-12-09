'use client';

import React, { useState, KeyboardEvent, useEffect } from 'react';
import styles from './index.module.css';
import { useStore } from '@/provider';
import QaModal from '@/components/QaModal';

const Landing = () => {
  const { setQaModalOpen } = useStore();
  const [questionInput, setQuestionInput] =
    useState('民用无人航天器无线电相关要求');

  // 确保 QaModal 初始状态为关闭
  useEffect(() => {
    setQaModalOpen?.(false);
  }, [setQaModalOpen]);

  const submitQuestion = (mode: 'chat' | 'web-search') => {
    const question = questionInput.trim();
    if (question) {
      sessionStorage.setItem('chat_search_query', question);
    }
    sessionStorage.setItem('qa_modal_mode', mode);
    setQaModalOpen?.(true);
  };

  const handleKeyPress = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      submitQuestion('chat');
    }
  };

  const handleQuickQuestion = (question: string) => {
    sessionStorage.setItem('chat_search_query', question);
    sessionStorage.setItem('qa_modal_mode', 'chat');
    setQaModalOpen?.(true);
  };

  const openQaModal = (mode: 'chat' | 'search' | 'web-search') => {
    sessionStorage.setItem('qa_modal_mode', mode);
    setQaModalOpen?.(true);
  };

  return (
    <>
      <QaModal />
      <div className={`${styles.page} ${styles.flexCol}`}>
        <div className={`${styles.box_1} ${styles.flexRow}`}>
          <img
            className={styles.image_1}
            referrerPolicy='no-referrer'
            src='/img/SketchPng4bd058e493ad33e266b577550a3a7f02786c07cfa7ba304aaab0e8f606b23707.png'
            alt='Logo'
          />
          <div className={styles.top_btns}>
            <button
              onClick={() => openQaModal('chat')}
              className={`${styles.group_1} ${styles.flexRow} ${styles.actionButton}`}
            >
              <img
                className={styles.thumbnail_1}
                referrerPolicy='no-referrer'
                src='/img/SketchPng130af4e6afeb35309844a32c09801e290c073d5baec6dcb33677fb44adf7d0c9.png'
                alt='Search Icon'
              />
              <span className={styles.text_1}>问问AI吧</span>
              <img
                className={styles.image_2}
                referrerPolicy='no-referrer'
                src='/img/SketchPng541f76058b8d9cff0a0875812a7815db77bfe4ab996112779cd31ceaaf38febe.png'
                alt='Divider'
              />
            </button>
            <button
              onClick={() => openQaModal('chat')}
              className={`${styles.textWrapper_1} ${styles.flexCol} ${styles.actionButton}`}
            >
              <span className={styles.text_2}>智能问答</span>
            </button>
          </div>
        </div>
        <div className={`${styles.textWrapper_2} ${styles.flexCol}`}>
          <span className={styles.text_3}>无线一点通</span>
          <span className={styles.paragraph_1}>
            「无线一点通」—— 上海无线电监测站官方 AI
            政策文件、技术标准等查询工具，专注无线电技术管理领域的政策文件、技术标准、
            <br />
            技术动态等信息检索，为无线电技术管理者、本市行业部门以及社会用户提供数据支持，助力本市无线电管理秩序规范有序。
          </span>
        </div>
        <div className={`${styles.box_2} ${styles.flexCol}`}>
          <div
            className={`${styles.group_2} ${styles.flexCol} ${styles.justifyEnd}`}
          >
            <div className={`${styles.box_3} ${styles.flexRow}`}>
              <img
                className={styles.image_3}
                referrerPolicy='no-referrer'
                src='/img/SketchPng493e835595efd5cac90de3db3925b36d69d9bf850c09f2d19d3e3062e745eb17.png'
                alt='Icon'
              />
              <div
                className={`${styles.group_3} ${styles.flexCol} ${styles.justifyBetween}`}
              >
                <span className={styles.text_4}>
                  「无线一点通」——&nbsp;上海无线电监测站官方&nbsp;AI&nbsp;查询工具，专注无线电站管理制度检索，覆盖合规规范、运营标准等核心内容，以智能技术简化查询流程，为从业者提供权威数据支持，助力合规高效办公。
                </span>
                <div
                  className={`${styles.imageText_1} ${styles.flexRow} ${styles.justifyBetween}`}
                >
                  <img
                    className={styles.image_4}
                    referrerPolicy='no-referrer'
                    src='/img/SketchPng452666f3cd5e33b93ad5304a166e579eb02c7d9f7f84d8c5fbc9a4a9f39adeb2.png'
                    alt='Support Icon'
                  />
                  <span className={styles.textGroup_1}>技术支持</span>
                </div>
              </div>
              <img
                className={styles.image_5}
                referrerPolicy='no-referrer'
                src='/img/SketchPng552151c2823c949dd02ac1b67746c46e7a7d350e1800708e4b0a3ff29ef2be3b.png'
                alt='Decoration'
              />
            </div>
            <div className={`${styles.textWrapper_3} ${styles.flexCol}`}>
              <span className={styles.text_5}>
                上海市无线电监测站&nbsp;◎&nbsp;2025.&nbsp;All&nbsp;rights&nbsp;reserved.
              </span>
            </div>
            <img
              className={styles.image_6}
              referrerPolicy='no-referrer'
              src='/img/SketchPnga7f9a50fd797d7d6b2f38aeb9a10244fac0c7ce7390e62466442aff72a5f7b55.png'
              alt='Background Decoration'
            />
            <div className={`${styles.box_4} ${styles.flexCol}`}>
              <div className={`${styles.imageWrapper_1} ${styles.flexRow}`}>
                <img
                  className={styles.image_7}
                  referrerPolicy='no-referrer'
                  src='/img/SketchPnga2617738b5ef9e34b9e03d113908a431b8f2555f4a8991daab58eeb8dd6846e2.png'
                  alt='Hidden'
                />
              </div>
              <div className={`${styles.section_1} ${styles.flexRow}`}>
                <button
                  onClick={() =>
                    handleQuickQuestion('民用无人航天器无线电相关要求')
                  }
                  className={`${styles.textWrapper_4} ${styles.flexCol} ${styles.actionButton}`}
                >
                  <span className={styles.text_6}>
                    民用无人航天器无线电相关要求
                  </span>
                </button>
              </div>

              <div className={`${styles.textWrapper_5} ${styles.flexCol}`}>
                <input
                  type='text'
                  id='questionInput'
                  placeholder='请输入您的问题...'
                  value={questionInput}
                  onChange={e => setQuestionInput(e.target.value)}
                  onKeyPress={handleKeyPress}
                  className={styles.questionInput}
                />
              </div>
              <button
                onClick={() => submitQuestion('chat')}
                className={`${styles.textWrapper_6} ${styles.flexCol} ${styles.actionButton}`}
              >
                <span className={styles.text_8}>AI智能问答</span>
              </button>
              <button
                onClick={() => submitQuestion('web-search')}
                className={`${styles.textWrapper_7} ${styles.flexCol} ${styles.actionButton}`}
              >
                <span className={styles.text_9}>互联网检索</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default Landing;
