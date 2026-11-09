import { useEffect, useRef } from "react";

const DONUTS = [
  { id: "one", x: 5, y: 17, size: 148 },
  { id: "two", x: 27, y: 70, size: 86 },
  { id: "three", x: 48, y: 8, size: 116 },
  { id: "four", x: 73, y: 34, size: 172 },
  { id: "five", x: 86, y: 78, size: 102 },
  { id: "six", x: 38, y: 43, size: 66 },
] as const;

export default function AmbientDonuts() {
  const layerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const layer = layerRef.current;
    if (!layer) return;

    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    if (reduceMotion.matches) return;

    const donuts = Array.from(
      layer.querySelectorAll<HTMLElement>(".ambient-donut"),
    );
    let frameId = 0;
    let pointerX = -1;
    let pointerY = -1;

    function resetDonuts() {
      for (const donut of donuts) {
        donut.style.setProperty("--pointer-shift-x", "0px");
        donut.style.setProperty("--pointer-shift-y", "0px");
      }
    }

    function applyPointerInfluence() {
      frameId = 0;
      if (pointerX < 0 || pointerY < 0 || reduceMotion.matches) {
        resetDonuts();
        return;
      }

      const bounds = layer.getBoundingClientRect();
      const proximityRadius = 285;

      for (const donut of donuts) {
        const x = Number(donut.dataset.x);
        const y = Number(donut.dataset.y);
        const size = Number(donut.dataset.size);
        const centerX = bounds.left + (window.innerWidth * x) / 100 + size / 2;
        const centerY = bounds.top + (window.innerHeight * y) / 100 + size / 2;
        const deltaX = centerX - pointerX;
        const deltaY = centerY - pointerY;
        const distance = Math.hypot(deltaX, deltaY);

        if (distance >= proximityRadius || distance === 0) {
          donut.style.setProperty("--pointer-shift-x", "0px");
          donut.style.setProperty("--pointer-shift-y", "0px");
          continue;
        }

        const influence = 1 - distance / proximityRadius;
        const strength = influence * 30;
        const directionX = deltaX / distance;
        const directionY = deltaY / distance;
        const drift = strength * 0.14;

        donut.style.setProperty(
          "--pointer-shift-x",
          `${directionX * strength - directionY * drift}px`,
        );
        donut.style.setProperty(
          "--pointer-shift-y",
          `${directionY * strength + directionX * drift}px`,
        );
      }
    }

    function handlePointerMove(event: PointerEvent) {
      if (event.pointerType !== "mouse") return;
      pointerX = event.clientX;
      pointerY = event.clientY;

      if (frameId === 0) {
        frameId = window.requestAnimationFrame(applyPointerInfluence);
      }
    }

    function handlePointerLeave() {
      pointerX = -1;
      pointerY = -1;
      if (frameId !== 0) {
        window.cancelAnimationFrame(frameId);
        frameId = 0;
      }
      resetDonuts();
    }

    function handleMotionPreferenceChange(event: MediaQueryListEvent) {
      if (event.matches) handlePointerLeave();
    }

    window.addEventListener("pointermove", handlePointerMove, { passive: true });
    window.addEventListener("blur", handlePointerLeave);
    document.documentElement.addEventListener("mouseleave", handlePointerLeave);
    reduceMotion.addEventListener("change", handleMotionPreferenceChange);

    return () => {
      window.removeEventListener("pointermove", handlePointerMove);
      window.removeEventListener("blur", handlePointerLeave);
      document.documentElement.removeEventListener("mouseleave", handlePointerLeave);
      reduceMotion.removeEventListener("change", handleMotionPreferenceChange);
      if (frameId !== 0) window.cancelAnimationFrame(frameId);
      resetDonuts();
    };
  }, []);

  return (
    <div ref={layerRef} className="ambient-donuts" aria-hidden="true">
      {DONUTS.map((donut, index) => (
        <span
          className={`ambient-donut ambient-donut--${index + 1}`}
          key={donut.id}
          data-x={donut.x}
          data-y={donut.y}
          data-size={donut.size}
        />
      ))}
    </div>
  );
}
