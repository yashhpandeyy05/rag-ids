'use client';

import React, { useEffect, useRef } from 'react';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import Lenis from '@studio-freight/lenis';

export interface ParallaxLayerItem {
  layer: string;
  src?: string;
  alt?: string;
  yPercent: number;
  title?: string;
}

export interface ParallaxComponentProps {
  title?: string;
  layers?: ParallaxLayerItem[];
  className?: string;
}

const DEFAULT_LAYERS: ParallaxLayerItem[] = [
  {
    layer: '1',
    src: 'https://images.unsplash.com/photo-1506744038136-46273834b3fb?auto=format&fit=crop&w=1600&q=80',
    alt: 'Distant Mountain Silhouette',
    yPercent: 70,
  },
  {
    layer: '2',
    src: 'https://images.unsplash.com/photo-1511497584788-87676104235f?auto=format&fit=crop&w=1600&q=80',
    alt: 'Forest Canopy Mist',
    yPercent: 55,
  },
  {
    layer: '3',
    title: 'Parallax',
    yPercent: 40,
  },
  {
    layer: '4',
    src: 'https://images.unsplash.com/photo-1470071459604-3b5ec3a7fe05?auto=format&fit=crop&w=1600&q=80',
    alt: 'Forefront Ridge',
    yPercent: 10,
  },
];

export function ParallaxComponent({
  title = 'Parallax',
  layers = DEFAULT_LAYERS,
  className = '',
}: ParallaxComponentProps) {
  const parallaxRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    gsap.registerPlugin(ScrollTrigger);

    const triggerElement = parallaxRef.current?.querySelector('[data-parallax-layers]');

    if (triggerElement) {
      const tl = gsap.timeline({
        scrollTrigger: {
          trigger: triggerElement,
          start: '0% 0%',
          end: '100% 0%',
          scrub: 0,
        },
      });

      layers.forEach((layerObj, idx) => {
        tl.to(
          triggerElement.querySelectorAll(`[data-parallax-layer="${layerObj.layer}"]`),
          {
            yPercent: layerObj.yPercent,
            ease: 'none',
          },
          idx === 0 ? undefined : '<'
        );
      });
    }

    const lenis = new Lenis();
    lenis.on('scroll', ScrollTrigger.update);
    const tickHandler = (time: number) => {
      lenis.raf(time * 1000);
    };
    gsap.ticker.add(tickHandler);
    gsap.ticker.lagSmoothing(0);

    return () => {
      ScrollTrigger.getAll().forEach((st) => st.kill());
      if (triggerElement) gsap.killTweensOf(triggerElement);
      gsap.ticker.remove(tickHandler);
      lenis.destroy();
    };
  }, [layers]);

  return (
    <div className={`parallax ${className}`} ref={parallaxRef}>
      <section className="parallax__header relative h-[100vh] w-full overflow-hidden bg-neutral-950">
        <div className="parallax__visuals relative h-full w-full">
          <div className="parallax__black-line-overflow absolute inset-x-0 -top-px h-px bg-neutral-950 z-20"></div>
          <div data-parallax-layers className="parallax__layers relative h-full w-full overflow-hidden">
            {layers.map((layer) => {
              if (layer.src) {
                return (
                  <img
                    key={layer.layer}
                    src={layer.src}
                    loading="eager"
                    data-parallax-layer={layer.layer}
                    alt={layer.alt || ''}
                    className="parallax__layer-img absolute inset-0 w-full h-full object-cover pointer-events-none will-change-transform"
                  />
                );
              }
              return (
                <div
                  key={layer.layer}
                  data-parallax-layer={layer.layer}
                  className="parallax__layer-title absolute inset-0 flex items-center justify-center z-10 pointer-events-none will-change-transform"
                >
                  <h2 className="parallax__title text-6xl sm:text-8xl md:text-9xl font-black tracking-tighter text-white uppercase drop-shadow-2xl">
                    {layer.title || title}
                  </h2>
                </div>
              );
            })}
          </div>
          <div className="parallax__fade absolute inset-x-0 bottom-0 h-40 bg-gradient-to-t from-neutral-950 to-transparent pointer-events-none z-10"></div>
        </div>
      </section>
      <section className="parallax__content relative min-h-[60vh] bg-neutral-950 text-white flex items-center justify-center p-8">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          width="120"
          height="120"
          viewBox="0 0 160 160"
          fill="none"
          className="osmo-icon-svg text-indigo-400 opacity-80"
        >
          <path
            d="M94.8284 53.8578C92.3086 56.3776 88 54.593 88 51.0294V0H72V59.9999C72 66.6273 66.6274 71.9999 60 71.9999H0V87.9999H51.0294C54.5931 87.9999 56.3777 92.3085 53.8579 94.8283L18.3431 130.343L29.6569 141.657L65.1717 106.142C67.684 103.63 71.9745 105.396 72 108.939V160L88.0001 160L88 99.9999C88 93.3725 93.3726 87.9999 100 87.9999H160V71.9999H108.939C105.407 71.9745 103.64 67.7091 106.12 65.1938L106.142 65.1716L141.657 29.6568L130.343 18.3432L94.8284 53.8578Z"
            fill="currentColor"
          ></path>
        </svg>
      </section>
    </div>
  );
}

export default ParallaxComponent;
