import {
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type {
  KeyboardEvent as ReactKeyboardEvent,
  PointerEvent as ReactPointerEvent,
} from "react";
import CodeMirror from "@uiw/react-codemirror";
import { java } from "@codemirror/lang-java";
import { python } from "@codemirror/lang-python";
import type { SupportedLanguage } from "../types/problem";

interface CodeEditorProps {
  language: SupportedLanguage;
  value: string;
  onChange: (value: string) => void;
}

interface ScrollMetrics {
  top: number;
  height: number;
  viewport: number;
}

const EMPTY_SCROLL_METRICS: ScrollMetrics = {
  top: 0,
  height: 0,
  viewport: 0,
};

export default function CodeEditor({
  language,
  value,
  onChange,
}: CodeEditorProps) {
  const extensions = useMemo(
    () => [language === "java" ? java() : python()],
    [language],
  );
  const [scrollMetrics, setScrollMetrics] =
    useState<ScrollMetrics>(EMPTY_SCROLL_METRICS);
  const scrollAreaId = "sky-high-source-code-scroll-area";
  const scrollElementRef = useRef<HTMLElement | null>(null);
  const scrollbarTrackRef = useRef<HTMLDivElement | null>(null);
  const dragOffsetRef = useRef<number | null>(null);
  const cleanupRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    return () => {
      cleanupRef.current?.();
      cleanupRef.current = null;
    };
  }, []);

  function refreshScrollMetrics(scroller: HTMLElement) {
    const next: ScrollMetrics = {
      top: scroller.scrollTop,
      height: scroller.scrollHeight,
      viewport: scroller.clientHeight,
    };

    setScrollMetrics((current) => {
      if (
        current.top === next.top &&
        current.height === next.height &&
        current.viewport === next.viewport
      ) {
        return current;
      }
      return next;
    });
  }

  function handleEditorCreated(view: Parameters<NonNullable<
    React.ComponentProps<typeof CodeMirror>["onCreateEditor"]
  >>[0]) {
    cleanupRef.current?.();

    const scroller = view.scrollDOM;
    scrollElementRef.current = scroller;
    scroller.id = scrollAreaId;

    const update = () => refreshScrollMetrics(scroller);
    scroller.addEventListener("scroll", update, { passive: true });

    const resizeObserver = new ResizeObserver(update);
    resizeObserver.observe(scroller);

    const content = scroller.querySelector(".cm-content");
    if (content) {
      resizeObserver.observe(content);
    }

    const mutationObserver = new MutationObserver(update);
    mutationObserver.observe(content ?? scroller, {
      childList: true,
      subtree: true,
      characterData: true,
    });

    update();
    requestAnimationFrame(update);

    cleanupRef.current = () => {
      scroller.removeEventListener("scroll", update);
      resizeObserver.disconnect();
      mutationObserver.disconnect();
      scrollElementRef.current = null;
    };
  }

  function getThumbMetrics(trackHeight: number) {
    const maxScroll = Math.max(
      0,
      scrollMetrics.height - scrollMetrics.viewport,
    );
    const thumbHeight =
      maxScroll > 0 && scrollMetrics.height > 0
        ? Math.min(
            trackHeight,
            Math.max(38, (scrollMetrics.viewport / scrollMetrics.height) * trackHeight),
          )
        : trackHeight;
    const thumbTravel = Math.max(0, trackHeight - thumbHeight);
    const thumbTop =
      maxScroll > 0
        ? (scrollMetrics.top / maxScroll) * thumbTravel
        : 0;

    return { maxScroll, thumbHeight, thumbTravel, thumbTop };
  }

  function scrollToPointer(clientY: number, pointerOffset: number) {
    const scroller = scrollElementRef.current;
    const track = scrollbarTrackRef.current;
    if (!scroller || !track) return;

    const rect = track.getBoundingClientRect();
    const maxScroll = Math.max(0, scroller.scrollHeight - scroller.clientHeight);
    const trackHeight = rect.height;
    const thumbHeight =
      maxScroll > 0
        ? Math.min(
            trackHeight,
            Math.max(38, (scroller.clientHeight / scroller.scrollHeight) * trackHeight),
          )
        : trackHeight;
    const thumbTravel = Math.max(1, trackHeight - thumbHeight);
    const thumbTop = Math.min(
      thumbTravel,
      Math.max(0, clientY - rect.top - pointerOffset),
    );

    scroller.scrollTop = maxScroll * (thumbTop / thumbTravel);
  }

  function handleScrollbarPointerDown(event: ReactPointerEvent<HTMLDivElement>) {
    if (event.button !== 0) return;
    event.preventDefault();

    const track = event.currentTarget;
    const rect = track.getBoundingClientRect();
    const pointerY = event.clientY - rect.top;
    const { thumbHeight, thumbTop } = getThumbMetrics(rect.height);
    const withinThumb =
      pointerY >= thumbTop && pointerY <= thumbTop + thumbHeight;

    dragOffsetRef.current = withinThumb
      ? pointerY - thumbTop
      : thumbHeight / 2;

    track.setPointerCapture(event.pointerId);
    scrollToPointer(event.clientY, dragOffsetRef.current);
  }

  function handleScrollbarPointerMove(event: ReactPointerEvent<HTMLDivElement>) {
    if (dragOffsetRef.current === null) return;
    event.preventDefault();
    scrollToPointer(event.clientY, dragOffsetRef.current);
  }

  function stopScrollbarDrag(event: ReactPointerEvent<HTMLDivElement>) {
    dragOffsetRef.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  }

  function handleScrollbarKeyDown(event: ReactKeyboardEvent<HTMLDivElement>) {
    const scroller = scrollElementRef.current;
    if (!scroller) return;

    const pageStep = Math.max(40, Math.floor(scroller.clientHeight * 0.85));
    switch (event.key) {
      case "ArrowDown":
        scroller.scrollTop += 40;
        break;
      case "ArrowUp":
        scroller.scrollTop -= 40;
        break;
      case "PageDown":
        scroller.scrollTop += pageStep;
        break;
      case "PageUp":
        scroller.scrollTop -= pageStep;
        break;
      case "Home":
        scroller.scrollTop = 0;
        break;
      case "End":
        scroller.scrollTop = scroller.scrollHeight;
        break;
      default:
        return;
    }

    event.preventDefault();
  }

  const trackHeight = scrollbarTrackRef.current?.clientHeight ?? 0;
  const { maxScroll, thumbHeight, thumbTop } = getThumbMetrics(trackHeight);

  return (
    <div className="code-editor" aria-label="Source code editor">
      <CodeMirror
        value={value}
        height="100%"
        width="100%"
        theme="dark"
        extensions={extensions}
        onChange={onChange}
        onCreateEditor={handleEditorCreated}
        basicSetup={{
          lineNumbers: true,
          foldGutter: true,
          highlightActiveLine: true,
          highlightActiveLineGutter: true,
          tabSize: 4,
        }}
        aria-label={`${language.toUpperCase()} source editor`}
      />

      <div
        ref={scrollbarTrackRef}
        className="code-editor-scrollbar"
        role="scrollbar"
        aria-label="Scroll source code"
        aria-controls={scrollAreaId}
        aria-orientation="vertical"
        aria-valuemin={0}
        aria-valuemax={Math.round(maxScroll)}
        aria-valuenow={Math.min(
          Math.round(scrollMetrics.top),
          Math.round(maxScroll),
        )}
        tabIndex={0}
        onKeyDown={handleScrollbarKeyDown}
        onPointerDown={handleScrollbarPointerDown}
        onPointerMove={handleScrollbarPointerMove}
        onPointerUp={stopScrollbarDrag}
        onPointerCancel={stopScrollbarDrag}
      >
        <div
          className="code-editor-scrollbar-thumb"
          style={{
            height: `${thumbHeight}px`,
            transform: `translateY(${thumbTop}px)`,
          }}
        />
      </div>
    </div>
  );
}
