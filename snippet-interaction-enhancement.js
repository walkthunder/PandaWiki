/**
 * 无线随申查 - 交互增强脚本
 * 提供动态效果、用户交互优化和性能监控
 */

(function() {
  'use strict';

  // ========================================
  // 1. 页面加载完成后初始化
  // ========================================
  
  window.addEventListener('DOMContentLoaded', function() {
    initEnhancements();
  });

  function initEnhancements() {
    // 初始化所有增强功能
    initScrollEffects();
    initSearchBoxEnhancements();
    initHotTopicsInteraction();
    initHeaderScrollEffect();
    initParallaxEffect();
    initPerformanceOptimization();
    initAccessibilityEnhancements();
    initMobileDialogCloseButton(); // 新增：移动端对话框关闭按钮
  }

  // ========================================
  // 2. 滚动效果增强
  // ========================================
  
  function initScrollEffects() {
    let ticking = false;
    let lastScrollTop = 0;

    window.addEventListener('scroll', function() {
      if (!ticking) {
        window.requestAnimationFrame(function() {
          handleScroll();
          ticking = false;
        });
        ticking = true;
      }
    }, { passive: true });

    function handleScroll() {
      const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
      
      // 元素渐入动画
      const elements = document.querySelectorAll('.mui-15tsxb4 > *');
      elements.forEach(function(el, index) {
        const rect = el.getBoundingClientRect();
        const isVisible = rect.top < window.innerHeight * 0.9;
        
        if (isVisible && !el.classList.contains('animated')) {
          el.classList.add('animated');
          el.style.animation = 'fadeInUp 0.6s cubic-bezier(0.4, 0, 0.2, 1) ' + (index * 0.1) + 's backwards';
        }
      });

      lastScrollTop = scrollTop;
    }
  }

  // ========================================
  // 3. 搜索框增强
  // ========================================
  
  function initSearchBoxEnhancements() {
    const searchBox = document.querySelector('.mui-14pi0he');
    const searchInput = document.querySelector('.mui-d8i322');
    const searchButton = document.querySelector('.mui-16ky6fx');

    if (!searchBox || !searchInput || !searchButton) return;
    
    // 检测移动设备
    const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent) || window.innerWidth < 600;

    // 搜索框获得焦点时的效果（移动端简化）
    searchInput.addEventListener('focus', function() {
      if (!isMobile) {
        searchBox.style.transform = 'translateY(-4px) scale(1.01)';
        createRipple(searchBox);
      }
    });

    searchInput.addEventListener('blur', function() {
      if (!searchInput.value && !isMobile) {
        searchBox.style.transform = '';
      }
    });

    // 输入时的动态效果（移动端简化）
    let typingTimer;
    searchInput.addEventListener('input', function() {
      clearTimeout(typingTimer);
      
      if (!isMobile) {
        searchInput.style.transform = 'scale(1.01)';
        
        typingTimer = setTimeout(function() {
          searchInput.style.transform = '';
        }, 300);
      }
    });

    // 回车键搜索
    searchInput.addEventListener('keypress', function(e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        triggerSearch();
      }
    });

    // 按钮点击增强
    searchButton.addEventListener('click', function(e) {
      createButtonRipple(e, searchButton);
      triggerSearch();
    });

    function triggerSearch() {
      const query = searchInput.value.trim();
      if (query) {
        // 添加搜索动画
        searchButton.style.transform = 'scale(0.95)';
        setTimeout(function() {
          searchButton.style.transform = '';
          console.log('搜索:', query);
          // 这里可以添加实际的搜索逻辑
        }, 150);
      } else {
        // 摇晃动画提示输入
        searchBox.style.animation = 'shake 0.5s';
        setTimeout(function() {
          searchBox.style.animation = '';
        }, 500);
      }
    }
  }

  // ========================================
  // 4. 热点问题交互增强
  // ========================================
  
  function initHotTopicsInteraction() {
    const hotTopics = document.querySelectorAll('.mui-15br0ju');
    const searchInput = document.querySelector('.mui-d8i322');
    
    // 检测是否为移动设备
    const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent) || window.innerWidth < 600;

    hotTopics.forEach(function(topic, index) {
      // 添加延迟动画（移动端也保留）
      topic.style.animationDelay = (0.8 + index * 0.1) + 's';
      
      // 点击填充搜索框
      topic.addEventListener('click', function() {
        const text = topic.textContent.trim();
        if (searchInput) {
          // 移动端直接填充，PC端使用打字机效果
          if (isMobile) {
            searchInput.value = text;
            searchInput.focus();
          } else {
            typeWriter(searchInput, text, 30);
            setTimeout(function() {
              searchInput.focus();
            }, text.length * 30 + 100);
          }
        }
        
        // 添加点击反馈
        createRipple(topic);
      });

      // PC端鼠标移动视差效果（移动端禁用）
      if (!isMobile) {
        topic.addEventListener('mousemove', function(e) {
          const rect = topic.getBoundingClientRect();
          const x = e.clientX - rect.left;
          const y = e.clientY - rect.top;
          
          const centerX = rect.width / 2;
          const centerY = rect.height / 2;
          
          const deltaX = (x - centerX) / centerX;
          const deltaY = (y - centerY) / centerY;
          
          topic.style.transform = 'translateY(-3px) rotateX(' + (-deltaY * 5) + 'deg) rotateY(' + (deltaX * 5) + 'deg)';
        });

        topic.addEventListener('mouseleave', function() {
          topic.style.transform = '';
        });
      }
    });
  }

  // ========================================
  // 5. 导航栏滚动效果
  // ========================================
  
  function initHeaderScrollEffect() {
    const header = document.querySelector('.mui-f4iiet');
    if (!header) return;

    let lastScroll = 0;

    window.addEventListener('scroll', function() {
      const currentScroll = window.pageYOffset;

      if (currentScroll > 100) {
        header.style.backgroundColor = 'rgba(255, 255, 255, 0.95)';
        header.style.boxShadow = '0 4px 30px rgba(0, 0, 0, 0.08)';
      } else {
        header.style.backgroundColor = 'rgba(255, 255, 255, 0.85)';
        header.style.boxShadow = '0 2px 20px rgba(0, 0, 0, 0.03)';
      }

      // 滚动方向检测 (可选：隐藏/显示导航栏)
      if (currentScroll > lastScroll && currentScroll > 500) {
        // 向下滚动
        // header.style.transform = 'translateY(-100%)';
      } else {
        // 向上滚动
        header.style.transform = 'translateY(0)';
      }

      lastScroll = currentScroll;
    }, { passive: true });
  }

  // ========================================
  // 6. 视差效果
  // ========================================
  
  function initParallaxEffect() {
    const background = document.querySelector('.mui-1x3niqi');
    if (!background) return;

    window.addEventListener('scroll', function() {
      const scrolled = window.pageYOffset;
      const parallax = scrolled * 0.5;
      
      if (background.style.backgroundImage && background.style.backgroundImage !== 'none') {
        background.style.backgroundPositionY = parallax + 'px';
      }
    }, { passive: true });
  }

  // ========================================
  // 7. 性能优化
  // ========================================
  
  function initPerformanceOptimization() {
    // 图片懒加载
    if ('IntersectionObserver' in window) {
      const imageObserver = new IntersectionObserver(function(entries) {
        entries.forEach(function(entry) {
          if (entry.isIntersecting) {
            const img = entry.target;
            if (img.dataset.src) {
              img.src = img.dataset.src;
              img.removeAttribute('data-src');
              imageObserver.unobserve(img);
            }
          }
        });
      });

      document.querySelectorAll('img[data-src]').forEach(function(img) {
        imageObserver.observe(img);
      });
    }

    // 防抖函数
    window.debounce = function(func, wait) {
      let timeout;
      return function() {
        const context = this;
        const args = arguments;
        clearTimeout(timeout);
        timeout = setTimeout(function() {
          func.apply(context, args);
        }, wait);
      };
    };

    // 节流函数
    window.throttle = function(func, limit) {
      let inThrottle;
      return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
          func.apply(context, args);
          inThrottle = true;
          setTimeout(function() {
            inThrottle = false;
          }, limit);
        }
      };
    };
  }

  // ========================================
  // 8. 无障碍增强
  // ========================================
  
  function initAccessibilityEnhancements() {
    // 键盘导航支持
    document.addEventListener('keydown', function(e) {
      if (e.key === '/' && e.ctrlKey) {
        e.preventDefault();
        const searchInput = document.querySelector('.mui-d8i322');
        if (searchInput) {
          searchInput.focus();
        }
      }
    });

    // 添加ARIA标签
    const searchInput = document.querySelector('.mui-d8i322');
    if (searchInput && !searchInput.hasAttribute('aria-label')) {
      searchInput.setAttribute('aria-label', '搜索查询输入框');
    }

    const searchButton = document.querySelector('.mui-16ky6fx');
    if (searchButton && !searchButton.hasAttribute('aria-label')) {
      searchButton.setAttribute('aria-label', 'AI智能问答按钮');
    }
  }

  // ========================================
  // 9. 移动端对话框关闭按钮
  // ========================================
  
  function initMobileDialogCloseButton() {
    // 检测是否为移动端（宽度 < 1200px）
    function isMobileView() {
      return window.innerWidth < 1200;
    }

    // 创建关闭按钮
    function createCloseButton() {
      const closeBtn = document.createElement('button');
      closeBtn.className = 'mobile-dialog-close-btn';
      closeBtn.innerHTML = '×'; // 使用 × 符号
      closeBtn.setAttribute('aria-label', '关闭对话框');
      closeBtn.setAttribute('title', '关闭 (Esc)');
      
      // 添加点击事件
      closeBtn.addEventListener('click', function() {
        // 模拟 Esc 键按下
        const escEvent = new KeyboardEvent('keydown', {
          key: 'Escape',
          keyCode: 27,
          code: 'Escape',
          which: 27,
          bubbles: true,
          cancelable: true
        });
        document.dispatchEvent(escEvent);
        
        // 如果上面的方法不生效，尝试直接关闭对话框
        const dialog = closeBtn.closest('.MuiDialog-root, .MuiPopover-root, .MuiModal-root');
        if (dialog) {
          // 尝试找到并点击 backdrop 或关闭按钮
          const backdrop = dialog.querySelector('.MuiBackdrop-root');
          if (backdrop) {
            backdrop.click();
          }
        }
      });
      
      return closeBtn;
    }

    // 检查并添加关闭按钮
    function checkAndAddCloseButton() {
      // 只在移动端执行
      if (!isMobileView()) {
        return;
      }

      // 查找所有打开的对话框/弹窗
      const dialogs = document.querySelectorAll('.MuiDialog-root, .MuiPopover-root, .MuiModal-root');
      
      dialogs.forEach(function(dialog) {
        // 检查是否已经有关闭按钮
        if (dialog.querySelector('.mobile-dialog-close-btn')) {
          return;
        }

        // 检查是否有 Esc 按钮（包括各种可能的选择器）
        const hasEscButton = dialog.querySelector(
          'button.mui-z8whtb, ' +
          'button:has-text("Esc"), ' +
          'button[aria-label*="Esc"], ' +
          'button[title*="Esc"]'
        );

        // 如果没有 Esc 按钮，添加关闭按钮
        if (!hasEscButton) {
          const paper = dialog.querySelector('.MuiPaper-root, .MuiDialog-paper');
          if (paper) {
            // 检查是否已有关闭按钮
            if (!paper.querySelector('.mobile-dialog-close-btn')) {
              const closeBtn = createCloseButton();
              paper.style.position = 'relative'; // 确保相对定位
              paper.insertBefore(closeBtn, paper.firstChild);
            }
          }
        }
      });
    }

    // 监听 DOM 变化，当有新的对话框出现时自动添加按钮
    const observer = new MutationObserver(function(mutations) {
      mutations.forEach(function(mutation) {
        if (mutation.addedNodes.length) {
          // 延迟执行，等待 DOM 完全渲染
          setTimeout(checkAndAddCloseButton, 100);
        }
      });
    });

    // 开始监听
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });

    // 监听窗口大小变化
    let resizeTimer;
    window.addEventListener('resize', function() {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function() {
        // 如果从移动端切换到桌面端，移除所有移动端按钮
        if (!isMobileView()) {
          const mobileButtons = document.querySelectorAll('.mobile-dialog-close-btn');
          mobileButtons.forEach(function(btn) {
            btn.remove();
          });
        } else {
          checkAndAddCloseButton();
        }
      }, 250);
    });

    // 初始检查
    checkAndAddCloseButton();
    
    // 定期检查（防止遗漏）
    setInterval(checkAndAddCloseButton, 2000);
  }

  // ========================================
  // 工具函数
  // ========================================
  
  // 水波纹效果
  function createRipple(element) {
    const ripple = document.createElement('span');
    ripple.style.position = 'absolute';
    ripple.style.borderRadius = '50%';
    ripple.style.background = 'rgba(66, 133, 244, 0.3)';
    ripple.style.width = '20px';
    ripple.style.height = '20px';
    ripple.style.marginTop = '-10px';
    ripple.style.marginLeft = '-10px';
    ripple.style.top = '50%';
    ripple.style.left = '50%';
    ripple.style.animation = 'ripple 0.6s ease-out';
    ripple.style.pointerEvents = 'none';

    element.style.position = 'relative';
    element.appendChild(ripple);

    setTimeout(function() {
      ripple.remove();
    }, 600);
  }

  // 按钮水波纹效果
  function createButtonRipple(event, button) {
    const ripple = document.createElement('span');
    const rect = button.getBoundingClientRect();
    
    ripple.style.position = 'absolute';
    ripple.style.borderRadius = '50%';
    ripple.style.background = 'rgba(255, 255, 255, 0.5)';
    ripple.style.width = '10px';
    ripple.style.height = '10px';
    ripple.style.left = (event.clientX - rect.left - 5) + 'px';
    ripple.style.top = (event.clientY - rect.top - 5) + 'px';
    ripple.style.animation = 'ripple 0.6s ease-out';
    ripple.style.pointerEvents = 'none';

    button.appendChild(ripple);

    setTimeout(function() {
      ripple.remove();
    }, 600);
  }

  // 打字机效果
  function typeWriter(element, text, speed) {
    element.value = '';
    let i = 0;
    
    function type() {
      if (i < text.length) {
        element.value += text.charAt(i);
        i++;
        setTimeout(type, speed);
      }
    }
    
    type();
  }

  // 添加动画样式
  const style = document.createElement('style');
  style.textContent = `
    @keyframes ripple {
      0% {
        transform: scale(0);
        opacity: 1;
      }
      100% {
        transform: scale(50);
        opacity: 0;
      }
    }

    @keyframes shake {
      0%, 100% { transform: translateX(0); }
      10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
      20%, 40%, 60%, 80% { transform: translateX(5px); }
    }

    .animated {
      opacity: 1 !important;
    }
  `;
  document.head.appendChild(style);

})();
