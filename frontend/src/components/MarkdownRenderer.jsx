import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

/**
 * Render inline markdown elements: **bold**, *italic*, `code`.
 */
function renderInline(text) {
  if (!text) return null;

  // 1. Split by inline code `...`
  const codeParts = text.split(/(`[^`]+`)/g);

  return codeParts.map((part, i) => {
    if (part.startsWith('`') && part.endsWith('`')) {
      return (
        <code
          key={i}
          className="rounded bg-slate-200/80 px-1.5 py-0.5 font-mono text-[11px] font-semibold text-slate-800"
        >
          {part.slice(1, -1)}
        </code>
      );
    }

    // 2. Split by bold **...**
    const boldParts = part.split(/(\*\*[^*]+\*\*)/g);
    return boldParts.map((bPart, j) => {
      if (bPart.startsWith('**') && bPart.endsWith('**')) {
        return (
          <strong key={`${i}-${j}`} className="font-semibold text-slate-900">
            {bPart.slice(2, -2)}
          </strong>
        );
      }

      // 3. Split by italic *...*
      const italicParts = bPart.split(/(\*[^*]+\*)/g);
      return italicParts.map((iPart, k) => {
        if (iPart.startsWith('*') && iPart.endsWith('*') && !iPart.startsWith('**')) {
          return (
            <em key={`${i}-${j}-${k}`} className="italic text-slate-800">
              {iPart.slice(1, -1)}
            </em>
          );
        }
        return iPart;
      });
    });
  });
}

/**
 * Render fenced code blocks with language tag and copy-to-clipboard button.
 */
function CodeBlock({ code, language }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="my-3 overflow-hidden rounded-xl border border-slate-700/60 bg-slate-900 text-slate-100 shadow-sm">
      <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950/70 px-3.5 py-1.5 text-[11px] text-slate-400">
        <span className="font-mono text-[10px] font-semibold uppercase tracking-wider text-brand-300">
          {language || 'code'}
        </span>
        <button
          type="button"
          onClick={handleCopy}
          className="inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-[11px] font-medium text-slate-300 transition-colors hover:bg-slate-800 hover:text-white"
          title="Copy code to clipboard"
        >
          {copied ? (
            <>
              <Check className="h-3 w-3 text-emerald-400" />
              <span className="text-emerald-400">Copied</span>
            </>
          ) : (
            <>
              <Copy className="h-3 w-3 text-slate-400" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>
      <pre className="overflow-x-auto p-3.5 font-mono text-xs leading-relaxed text-emerald-300">
        <code>{code}</code>
      </pre>
    </div>
  );
}

/**
 * Lightweight, zero-dependency Markdown parser for Copilot chat responses.
 * Parses headers (#, ##, ###), bold (**), italic (*), code (` and ```), and lists (- / 1.).
 */
export default function MarkdownRenderer({ content }) {
  if (!content) return null;

  // Split content into code blocks vs regular text chunks
  const chunks = [];
  const codeBlockRegex = /```([a-zA-Z0-9_-]*)\n?([\s\S]*?)```/g;
  let lastIndex = 0;
  let match;

  while ((match = codeBlockRegex.exec(content)) !== null) {
    if (match.index > lastIndex) {
      chunks.push({
        type: 'text',
        text: content.slice(lastIndex, match.index),
      });
    }
    chunks.push({
      type: 'code',
      language: match[1],
      code: match[2].trim(),
    });
    lastIndex = codeBlockRegex.lastIndex;
  }

  if (lastIndex < content.length) {
    chunks.push({
      type: 'text',
      text: content.slice(lastIndex),
    });
  }

  return (
    <div className="space-y-2 text-xs sm:text-sm leading-relaxed text-slate-800">
      {chunks.map((chunk, chunkIdx) => {
        if (chunk.type === 'code') {
          return (
            <CodeBlock
              key={chunkIdx}
              language={chunk.language}
              code={chunk.code}
            />
          );
        }

        const lines = chunk.text.split('\n');
        const elements = [];
        let currentList = null;

        const flushList = () => {
          if (currentList) {
            if (currentList.type === 'ul') {
              elements.push(
                <ul
                  key={`ul-${elements.length}`}
                  className="my-2 ml-4 list-disc space-y-1 text-slate-700"
                >
                  {currentList.items.map((item, i) => (
                    <li key={i}>{item}</li>
                  ))}
                </ul>
              );
            } else {
              elements.push(
                <ol
                  key={`ol-${elements.length}`}
                  className="my-2 ml-4 list-decimal space-y-1.5 text-slate-700"
                >
                  {currentList.items.map((item, i) => (
                    <li key={i}>{item}</li>
                  ))}
                </ol>
              );
            }
            currentList = null;
          }
        };

        lines.forEach((rawLine, lineIdx) => {
          const line = rawLine.trim();

          if (!line) {
            flushList();
            return;
          }

          // Heading 4 or 3: ### ...
          if (line.startsWith('### ')) {
            flushList();
            elements.push(
              <h4
                key={`h3-${lineIdx}`}
                className="mt-3 mb-1 text-xs sm:text-sm font-bold text-slate-900 tracking-tight"
              >
                {renderInline(line.slice(4))}
              </h4>
            );
            return;
          }

          // Heading 2: ## ...
          if (line.startsWith('## ')) {
            flushList();
            elements.push(
              <h3
                key={`h2-${lineIdx}`}
                className="mt-3.5 mb-1 text-sm font-bold text-slate-900 tracking-tight"
              >
                {renderInline(line.slice(3))}
              </h3>
            );
            return;
          }

          // Heading 1: # ...
          if (line.startsWith('# ')) {
            flushList();
            elements.push(
              <h2
                key={`h1-${lineIdx}`}
                className="mt-4 mb-1.5 text-base font-bold text-slate-900 tracking-tight"
              >
                {renderInline(line.slice(2))}
              </h2>
            );
            return;
          }

          // Bullet list item: - ... or * ...
          if (/^[-*]\s+/.test(line)) {
            const itemText = line.replace(/^[-*]\s+/, '');
            if (!currentList || currentList.type !== 'ul') {
              flushList();
              currentList = { type: 'ul', items: [] };
            }
            currentList.items.push(renderInline(itemText));
            return;
          }

          // Numbered list item: 1. ...
          if (/^\d+\.\s+/.test(line)) {
            const itemText = line.replace(/^\d+\.\s+/, '');
            if (!currentList || currentList.type !== 'ol') {
              flushList();
              currentList = { type: 'ol', items: [] };
            }
            currentList.items.push(renderInline(itemText));
            return;
          }

          // Regular paragraph
          flushList();
          elements.push(
            <p key={`p-${lineIdx}`} className="leading-relaxed">
              {renderInline(line)}
            </p>
          );
        });

        flushList();
        return <React.Fragment key={chunkIdx}>{elements}</React.Fragment>;
      })}
    </div>
  );
}
