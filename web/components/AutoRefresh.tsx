'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

interface Props {
  seconds: number;
  updatedText: string;
  pauseLabel: string;
  resumeLabel: string;
}

/** Asks the server for fresh data on a timer. The interval comes from the settings table. */
export function AutoRefresh({ seconds, updatedText, pauseLabel, resumeLabel }: Props) {
  const router = useRouter();
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    if (paused || seconds <= 0) return;
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') router.refresh();
    }, seconds * 1000);
    return () => clearInterval(timer);
  }, [paused, seconds, router]);

  return (
    <div className="refresh">
      <span className="num" aria-live="off">
        {updatedText}
      </span>
      <button type="button" onClick={() => setPaused((p) => !p)} aria-pressed={paused}>
        {paused ? resumeLabel : pauseLabel}
      </button>
    </div>
  );
}
