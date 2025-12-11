'use client';

import React, {
  useState,
  KeyboardEvent,
  useEffect,
  useMemo,
  useRef,
} from 'react';
import styles from './index.module.css';
import { useStore } from '@/provider';
import QaModal from '@/components/QaModal';

const Landing = () => {
  const { setQaModalOpen, kbDetail } = useStore();
  const [questionInput, setQuestionInput] = useState('');
  const [showComingSoonModal, setShowComingSoonModal] = useState(false);
  const [showVideo, setShowVideo] = useState(true);
  const [showRobot, setShowRobot] = useState(false);
  const videoRef = useRef<HTMLVideoElement>(null);

  // Get quick questions from banner config's hot_search
  const quickQuestions = useMemo(() => {
    const bannerConfig = kbDetail?.settings?.web_app_landing_configs?.find(
      config => config.type === 'banner',
    );
    return bannerConfig?.banner_config?.hot_search || [];
  }, [kbDetail?.settings?.web_app_landing_configs]);

  useEffect(() => {
    setQaModalOpen?.(false);
  }, [setQaModalOpen]);

  useEffect(() => {
    const video = videoRef.current;
    if (video) {
      const handleVideoEnd = () => {
        setShowVideo(false);
        // 延迟800ms后显示机器人
        setTimeout(() => {
          setShowRobot(true);
        }, 800);
      };

      video.addEventListener('ended', handleVideoEnd);

      return () => {
        video.removeEventListener('ended', handleVideoEnd);
      };
    }
  }, []);

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

  const handleViewMore = () => {
    setShowComingSoonModal(true);
  };

  const closeComingSoonModal = () => {
    setShowComingSoonModal(false);
  };

  return (
    <>
      <QaModal />

      {/* Coming Soon Modal */}
      {showComingSoonModal && (
        <div className={styles.modalOverlay} onClick={closeComingSoonModal}>
          <div
            className={styles.modalContent}
            onClick={e => e.stopPropagation()}
          >
            <div className={styles.modalIcon}>
              <svg width='64' height='64' viewBox='0 0 64 64' fill='none'>
                <circle
                  cx='32'
                  cy='32'
                  r='28'
                  stroke='#3A8CD8'
                  strokeWidth='3'
                  strokeLinecap='round'
                  strokeDasharray='4 4'
                />
                <path
                  d='M32 20V34L40 38'
                  stroke='#3A8CD8'
                  strokeWidth='3'
                  strokeLinecap='round'
                  strokeLinejoin='round'
                />
              </svg>
            </div>
            <h2 className={styles.modalTitle}>功能上线准备中</h2>
            <p className={styles.modalMessage}>
              我们正在努力完善这个功能，敬请期待！
            </p>
            <button
              className={styles.modalButton}
              onClick={closeComingSoonModal}
            >
              知道了
            </button>
          </div>
        </div>
      )}

      <div className={`${styles.page} ${styles.flexCol}`}>
        {/* Header */}
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

        {/* Hero Section */}
        <div
          className={`${styles.section_3} ${styles.flexCol} ${styles.justifyEnd}`}
        >
          {showVideo && (
            <>
              <video
                ref={videoRef}
                className={styles.videoBackground}
                autoPlay
                muted
                playsInline
              >
                <source src='/img/10406080034425884988.mp4' type='video/mp4' />
              </video>
              <div className={styles.videoOverlay} />
            </>
          )}
          {!showVideo && <div className={styles.staticBackground} />}
          <div className={`${styles.group_6} ${styles.flexRow}`}>
            <img
              className={styles.image_8}
              referrerPolicy='no-referrer'
              src='/img/SketchPng2dec881fd33e41302a8af79dd5fcb53d551d08343fe751e3996967f2aec32c0d.png'
              alt='Title'
            />
            <div className={styles.box_8} />
          </div>
          <span className={styles.paragraph_1}>
            「无线一点通」—— 上海无线电监测站官方 AI
            政策文件、技术标准等查询工具，专注无线电技术管理领域的政策文件、技术标准、
            <br />
            技术动态等信息检索，为无线电技术管理者、本市行业部门以及社会用户提供数据支持，助力本市无线电管理秩序规范有序。
          </span>

          {/* Search Box */}
          <div className={`${styles.block_2} ${styles.flexRow}`}>
            <input
              type='text'
              className={styles.text_3}
              placeholder='输入你的无线电相关问题，AI智能为您解答'
              value={questionInput}
              onChange={e => setQuestionInput(e.target.value)}
              onKeyPress={handleKeyPress}
            />
            <img
              className={styles.image_9}
              referrerPolicy='no-referrer'
              src='/img/SketchPng7d7afad26f2a058209a5bf5975ee6ba390be412f4f3aa74e428e7e8bea9b1fb3.png'
              alt='Icon'
            />
          </div>

          {/* Action Buttons */}
          <div
            className={`${styles.group_7} ${styles.flexCol} ${styles.justifyBetween}`}
          >
            <div
              className={`${styles.box_9} ${styles.flexRow} ${styles.justifyBetween}`}
            >
              {/* <button
                  onClick={() => submitQuestion('chat')}
                  className={`${styles.group_2} ${styles.flexCol} ${styles.actionButton}`}
                /> */}
              <button
                onClick={() => submitQuestion('chat')}
                className={`${styles.textWrapper_3} ${styles.flexCol} ${styles.actionButton}`}
              >
                <span className={styles.text_5}>AI智能问答</span>
              </button>
              <button
                onClick={() => submitQuestion('web-search')}
                className={`${styles.textWrapper_2} ${styles.flexCol} ${styles.actionButton}`}
              >
                <span className={styles.text_4}>互联网检索</span>
              </button>
            </div>
            <div
              className={`${styles.box_10} ${styles.flexRow} ${styles.justifyBetween}`}
            >
              {quickQuestions.slice(0, 3).map((question, index) => {
                const buttonClass =
                  index === 0
                    ? styles.box_4
                    : index === 1
                      ? styles.box_5
                      : styles.box_6;
                const imageTextClass =
                  index === 0
                    ? styles.imageText_9
                    : index === 1
                      ? styles.imageText_10
                      : styles.imageText_11;
                const thumbnailClass =
                  index === 0
                    ? styles.thumbnail_10
                    : index === 1
                      ? styles.thumbnail_11
                      : styles.thumbnail_12;
                const textGroupClass =
                  index === 0
                    ? styles.textGroup_1
                    : index === 1
                      ? styles.textGroup_2
                      : styles.textGroup_3;

                return (
                  <button
                    key={index}
                    onClick={() => handleQuickQuestion(question)}
                    className={`${buttonClass} ${styles.flexRow} ${styles.actionButton}`}
                  >
                    <div
                      className={`${imageTextClass} ${styles.flexRow} ${styles.justifyBetween}`}
                    >
                      <img
                        className={thumbnailClass}
                        referrerPolicy='no-referrer'
                        src='/img/SketchPng1b6fc4ad64a00602b4844eafc3076f7f88a9cc0adc6e7ff01ffa612f7e3a4168.png'
                        alt='Icon'
                      />
                      <span className={textGroupClass}>{question}</span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          <div
            className={`${styles.robot_container} ${showRobot ? styles.robot_visible : ''}`}
          >
            <img
              className={styles.image_11}
              referrerPolicy='no-referrer'
              src='/img/SketchPng5b6acc63f7c42a43d8d22c45170588b930c7dd37bd150de8a342678e70827c52.png'
              alt='Background'
            />
            <img
              className={styles.image_10}
              referrerPolicy='no-referrer'
              src='/img/SketchPngbec2256adb46b1e5d996a3f1510c30d527ea6b0e7db24bf2ee8dae5e7e0b1815.png'
              alt='Decoration'
            />
          </div>
        </div>

        {/* Feature Cards */}
        <div className={`${styles.list_2} ${styles.flexRow}`}>
          <div className={styles.listItems_1}>
            <div
              className={`${styles.box_11} ${styles.flexRow} ${styles.justifyBetween}`}
            >
              <img
                className={styles.label_2}
                referrerPolicy='no-referrer'
                src='/img/SketchPng582128a5c37fede3023fbeff4ac0d0413283340965d0399286c63c8b8cd3b63f.png'
                alt='Icon'
              />
              <span className={styles.text_6}>政策法规库</span>
            </div>
            <span className={styles.text_7}>
              汇集无线电管理相关法律法规、规章制度及政策文件，提供权威、全面的政策查询服务
            </span>
            <div
              className={`${styles.imageText_12} ${styles.flexRow} ${styles.justifyBetween}`}
              onClick={handleViewMore}
            >
              <span className={styles.textGroup_4}>查看更多</span>
              <img
                className={styles.thumbnail_13}
                referrerPolicy='no-referrer'
                src='/img/SketchPng2c89f1243574f8941d24e5f5e7c5195d9da6c902b0abf500a0145cbd80e3071e.png'
                alt='Arrow'
              />
            </div>
          </div>
          <div className={styles.listItems_1}>
            <div
              className={`${styles.box_11} ${styles.flexRow} ${styles.justifyBetween}`}
            >
              <img
                className={styles.label_2}
                referrerPolicy='no-referrer'
                src='/img/SketchPng608abafa0309b5d8753b887789d532d4ee082a93d97c37bd9f152ae3db76ecb8.png'
                alt='Icon'
              />
              <span className={styles.text_6}>技术标准查询</span>
            </div>
            <span className={styles.text_7}>
              整合无线电技术规范、行业标准及技术指南，为技术人员提供精准的标准查询与参考
            </span>
            <div
              className={`${styles.imageText_12} ${styles.flexRow} ${styles.justifyBetween}`}
              onClick={handleViewMore}
            >
              <span className={styles.textGroup_4}>查看更多</span>
              <img
                className={styles.thumbnail_13}
                referrerPolicy='no-referrer'
                src='/img/SketchPng2c89f1243574f8941d24e5f5e7c5195d9da6c902b0abf500a0145cbd80e3071e.png'
                alt='Arrow'
              />
            </div>
          </div>
          <div className={styles.listItems_1}>
            <div
              className={`${styles.box_11} ${styles.flexRow} ${styles.justifyBetween}`}
            >
              <img
                className={styles.label_2}
                referrerPolicy='no-referrer'
                src='/img/SketchPngfc2722fe5ead5b458494859ee3fefd03da8f1ce14e628001afc0544e2687f7a4.png'
                alt='Icon'
              />
              <span className={styles.text_6}>AI智能助手</span>
            </div>
            <span className={styles.text_7}>
              基于AI技术的智能问答系统，快速解答无线电管理、技术应用等各类专业问题
            </span>
            <div
              className={`${styles.imageText_12} ${styles.flexRow} ${styles.justifyBetween}`}
              onClick={() => openQaModal('chat')}
            >
              <span className={styles.textGroup_4}>查看更多</span>
              <img
                className={styles.thumbnail_13}
                referrerPolicy='no-referrer'
                src='/img/SketchPng2c89f1243574f8941d24e5f5e7c5195d9da6c902b0abf500a0145cbd80e3071e.png'
                alt='Arrow'
              />
            </div>
          </div>
        </div>

        {/* Spacer to push contact section to bottom */}
        <div className={styles.spacer} />

        {/* Contact Section */}
        <div className={`${styles.section_4} ${styles.flexRow}`}>
          <div className={`${styles.group_9} ${styles.flexCol}`}>
            <span className={styles.text_9}>技术支持与联系我们</span>
            <div
              className={`${styles.imageText_13} ${styles.flexRow} ${styles.justifyBetween}`}
            >
              <img
                className={styles.thumbnail_14}
                referrerPolicy='no-referrer'
                src='/img/SketchPnge33e963cbb993d732d8b228905a51d25a733e79a4354aabe5ef2cefccdb897a0.png'
                alt='Location'
              />
              <span className={styles.textGroup_5}>
                联系地址：上海市淮海中路1329号
              </span>
            </div>
            <div
              className={`${styles.box_12} ${styles.flexRow} ${styles.justifyBetween}`}
            >
              <div
                className={`${styles.imageText_14} ${styles.flexRow} ${styles.justifyBetween}`}
              >
                <img
                  className={styles.thumbnail_7}
                  referrerPolicy='no-referrer'
                  src='/img/SketchPngf5326a2d6c0660a99dbd6a7413952e6c569055df0e9b74359fa4c6d49b88f361.png'
                  alt='Phone'
                />
                <span className={styles.textGroup_6}>技术支持： 算启智能</span>
              </div>
              <div
                className={`${styles.imageText_15} ${styles.flexRow} ${styles.justifyBetween}`}
              >
                <img
                  className={styles.thumbnail_8}
                  referrerPolicy='no-referrer'
                  src='/img/SketchPng4e3f6404ca892feefb799e424601f09cea5c65778ce80b79aa6da411f6305515.png'
                  alt='Email'
                />
                <span className={styles.textGroup_7}>
                  邮箱：info@webinfra.cloud
                </span>
              </div>
            </div>
          </div>
          <button
            onClick={() => openQaModal('chat')}
            className={`${styles.group_4} ${styles.flexRow} ${styles.actionButton}`}
          >
            <div
              className={`${styles.imageText_16} ${styles.flexRow} ${styles.justifyBetween}`}
            >
              <img
                className={styles.image_12}
                referrerPolicy='no-referrer'
                src='/img/SketchPnga4dbb097c40183efd2f28f0a5966ab6c5e4882e721f162ece20f8cdf9a118f9c.png'
                alt='Chat'
              />
              <span className={styles.textGroup_8}>在线咨询</span>
            </div>
          </button>
          <div className={styles.group_5} />
        </div>

        {/* Footer */}
        <div className={`${styles.textWrapper_4} ${styles.flexCol}`}>
          <span className={styles.text_10}>
            上海市无线电监测站&nbsp;◎&nbsp;2025.&nbsp;All&nbsp;rights&nbsp;reserved.
          </span>
        </div>
      </div>
    </>
  );
};

export default Landing;
