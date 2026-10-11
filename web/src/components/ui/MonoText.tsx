import { splitMono } from '../../monoText'

/** Text with its IP addresses and port numbers set in a monospace font. */
export default function MonoText({ children }: { children: string }) {
  return (
    <>
      {splitMono(children).map((p, i) =>
        p.mono ? (
          <span key={i} className="font-mono">
            {p.text}
          </span>
        ) : (
          p.text
        ),
      )}
    </>
  )
}
