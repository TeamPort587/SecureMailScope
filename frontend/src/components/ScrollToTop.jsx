import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';

/**
 * Automatically scrolls window to top on route navigation,
 * ensuring users always start at the top of the page unless
 * targeting a specific in-page hash anchor (e.g. #upload-section).
 */
export default function ScrollToTop() {
  const { pathname, hash } = useLocation();

  useEffect(() => {
    // Disable native browser scroll restoration so SPAs don't restore old positions
    if ('scrollRestoration' in window.history) {
      window.history.scrollRestoration = 'manual';
    }
  }, []);

  useEffect(() => {
    // If navigating to an in-page anchor, let the target element handle it
    if (hash) return;

    const resetScroll = () => {
      const html = document.documentElement;
      const originalScrollBehavior = html?.style?.scrollBehavior;
      if (html) html.style.scrollBehavior = 'auto';

      window.scrollTo(0, 0);
      if (document.documentElement) document.documentElement.scrollTop = 0;
      if (document.body) document.body.scrollTop = 0;

      if (html) {
        requestAnimationFrame(() => {
          html.style.scrollBehavior = originalScrollBehavior;
        });
      }
    };

    resetScroll();
    const frameId = requestAnimationFrame(resetScroll);
    const timerId = setTimeout(resetScroll, 50);

    return () => {
      cancelAnimationFrame(frameId);
      clearTimeout(timerId);
    };
  }, [pathname, hash]);

  return null;
}
