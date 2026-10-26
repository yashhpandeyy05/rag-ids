'use client';

import React, { useEffect, useRef, useState, useMemo } from 'react';
import './GhostType.css';

/**
 * GhostType Component - React Bits Pro
 * A headline that writes itself with AI-style ghost completions.
 *
 * @param {Object} props
 * @param {string} props.text - Anchor headline text that types first and remains persistent
 * @param {string[]} props.completions - Sequential ending phrases suggested as ghost text
 * @param {string} [props.as='h1'] - HTML element tag ('h1' | 'h2' | 'h3' | 'h4' | 'p' | 'div' | 'span')
 * @param {number} [props.typeSpeed=45] - Milliseconds per typed character for base text
 * @param {number} [props.streamSpeed=70] - Milliseconds per ghost completion unit
 * @param {'word' | 'char'} [props.streamBy='word'] - Stream ghost text word-by-word or character-by-character
 * @param {number} [props.thinkDelay=600] - Milliseconds pause before a suggestion appears
 * @param {number} [props.acceptDelay=1200] - Pause before ghost text is accepted with sweep
 * @param {number} [props.holdDelay=2200] - Duration full headline remains visible before next cycle
 * @param {number} [props.deleteSpeed=25] - Milliseconds per deleted character when cycling
 * @param {string} [props.textColor] - Custom text color (inherits by default)
 * @param {string} [props.accentColor='#7C9BFF'] - Caret and sweep animation highlight color
 * @param {number} [props.ghostOpacity=0.38] - Opacity scaling of the ghost completion text
 * @param {string} [props.fontFamily] - Custom font family
 * @param {number|string} [props.fontSize] - Font size in px or string
 * @param {number|string} [props.fontWeight=800] - Font weight
 * @param {number|string} [props.lineHeight=1.1] - Line height multiplier
 * @param {boolean} [props.loop=true] - Whether completions loop indefinitely
 * @param {string} [props.className=''] - Additional CSS classes
 * @param {React.CSSProperties} [props.style] - Inline styles
 */
export default function GhostType({
  text = 'Break something.',
  completions = [
    '\nWatch the model catch it.',
    '\nSee the detector name the threat.',
    '\nQuestion an analyst tied to MITRE ATT&CK.'
  ],
  as = 'h1',
  typeSpeed = 45,
  streamSpeed = 70,
  streamBy = 'word',
  thinkDelay = 600,
  acceptDelay = 1200,
  holdDelay = 2200,
  deleteSpeed = 25,
  textColor,
  accentColor = '#7C9BFF',
  ghostOpacity = 0.38,
  fontFamily,
  fontSize,
  fontWeight = 800,
  lineHeight = 1.1,
  loop = true,
  className = '',
  style = {}
}) {
  const [typedMain, setTypedMain] = useState('');
  const [ghostText, setGhostText] = useState('');
  const [isAccepted, setIsAccepted] = useState(false);
  const [completionIndex, setCompletionIndex] = useState(0);
  const [phase, setPhase] = useState('type-main'); // 'type-main' | 'think' | 'stream' | 'accept' | 'hold' | 'delete'

  const activeCompletion = useMemo(() => {
    return completions[completionIndex % completions.length] || '';
  }, [completions, completionIndex]);

  // Screen reader representation
  const srText = `${text} ${activeCompletion}`.replace(/\n/g, ' ');

  useEffect(() => {
    let timer;

    // Phase 1: Type the persistent anchor text
    if (phase === 'type-main') {
      if (typedMain.length < text.length) {
        const jitter = (Math.random() - 0.5) * 20;
        timer = setTimeout(() => {
          setTypedMain(text.slice(0, typedMain.length + 1));
        }, Math.max(15, typeSpeed + jitter));
      } else {
        timer = setTimeout(() => {
          setPhase('think');
        }, thinkDelay);
      }
    }

    // Phase 2: Pause / AI Think delay before ghost suggestion
    else if (phase === 'think') {
      timer = setTimeout(() => {
        setPhase('stream');
        setIsAccepted(false);
      }, thinkDelay);
    }

    // Phase 3: Stream in ghost suggestion
    else if (phase === 'stream') {
      if (ghostText.length < activeCompletion.length) {
        let nextLength = ghostText.length + 1;
        if (streamBy === 'word') {
          const remaining = activeCompletion.slice(ghostText.length);
          const nextSpace = remaining.indexOf(' ', 1);
          nextLength = nextSpace === -1 ? activeCompletion.length : ghostText.length + nextSpace + 1;
        }
        timer = setTimeout(() => {
          setGhostText(activeCompletion.slice(0, nextLength));
        }, streamSpeed);
      } else {
        timer = setTimeout(() => {
          setPhase('accept');
        }, acceptDelay);
      }
    }

    // Phase 4: Accept suggestion with accent sweep
    else if (phase === 'accept') {
      setIsAccepted(true);
      timer = setTimeout(() => {
        setPhase('hold');
      }, 700);
    }

    // Phase 5: Hold the complete headline
    else if (phase === 'hold') {
      timer = setTimeout(() => {
        if (completions.length > 1 || loop) {
          setPhase('delete');
        }
      }, holdDelay);
    }

    // Phase 6: Delete completion text to prepare for next suggestion
    else if (phase === 'delete') {
      if (ghostText.length > 0) {
        timer = setTimeout(() => {
          setGhostText(prev => prev.slice(0, -1));
        }, deleteSpeed);
      } else {
        setIsAccepted(false);
        setCompletionIndex(prev => (prev + 1) % completions.length);
        setPhase('think');
      }
    }

    return () => clearTimeout(timer);
  }, [
    phase,
    typedMain,
    ghostText,
    text,
    activeCompletion,
    completions.length,
    streamBy,
    typeSpeed,
    streamSpeed,
    thinkDelay,
    acceptDelay,
    holdDelay,
    deleteSpeed,
    loop
  ]);

  const Tag = as;

  const componentStyle = {
    '--gt-text': textColor || 'inherit',
    '--gt-accent': accentColor,
    '--gt-ghost-opacity': ghostOpacity,
    '--gt-font-size': typeof fontSize === 'number' ? `${fontSize}px` : fontSize || 'inherit',
    '--gt-font-weight': fontWeight,
    '--gt-line-height': lineHeight,
    ...(fontFamily ? { fontFamily } : {}),
    ...style
  };

  const isBlinking = phase === 'think' || phase === 'hold' || phase === 'accept';

  return (
    <Tag className={`ghost-type ${className}`.trim()} style={componentStyle}>
      {/* Accessible to screen readers */}
      <span className="ghost-type__sr-only">{srText}</span>

      {/* Visual Animation presentation */}
      <span aria-hidden="true">
        <span className="ghost-type__main">{typedMain}</span>
        {ghostText ? (
          <span className={isAccepted ? 'ghost-type__accepted' : 'ghost-type__ghost'}>
            {ghostText}
          </span>
        ) : null}
        <span
          className={`ghost-type__caret ${isBlinking ? 'ghost-type__caret--blink' : ''}`.trim()}
        />
      </span>
    </Tag>
  );
}
