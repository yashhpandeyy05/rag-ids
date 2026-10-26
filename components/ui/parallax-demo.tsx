// src/demos/default.tsx
import { ParallaxComponent } from '@/components/ui/parallax-scrolling';

export default function ParallaxDemo() {
  return (
    <>
      <ParallaxComponent />
      <div className="osmo-credits py-6 text-center text-sm text-neutral-400 bg-neutral-950">
        <p className="osmo-credits__p">
          Resource by{' '}
          <a
            target="_blank"
            rel="noopener noreferrer"
            href="https://www.osmo.supply/"
            className="osmo-credits__p-a text-indigo-400 underline hover:text-indigo-300"
          >
            Osmo
          </a>
        </p>
      </div>
    </>
  );
}
