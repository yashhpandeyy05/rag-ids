// This is a file with a demo for your component
// That's what users will see in the preview
// Create new files in this directory to add more demos

import PerspectiveTunnelHero from "@/components/ui/perspective-tunnel-hero";

export default function DemoOne() {
    return (
        <main className="min-h-screen w-full flex items-center justify-center bg-stone-100 dark:bg-stone-950 p-4 sm:p-6 md:p-8 transition-colors duration-300">
            <div className="w-full max-w-3xl">
                <PerspectiveTunnelHero />
            </div>
        </main>
    );
}
