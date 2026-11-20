// Keep personal paths and key material out of anything that gets published.
const SEP = String.raw`(?:\\\\|\\|\/)+`;
const LOCAL_TEMP = new RegExp(String.raw`[A-Za-z]:${SEP}Users${SEP}[^"\\\/\s]+${SEP}AppData${SEP}Local${SEP}Temp${SEP}tl-live-[A-Za-z0-9]+`, 'g');

/** Replace the local temp directory used by the live experiment (any slash style, JSON escaped or not) with a neutral path. */
export function scrub(text: string): string {
  return text.replace(LOCAL_TEMP, '/tmp/tripline-live').replace(/\/tmp\/tripline-live(?:\\\\|\\|\/)+/g, '/tmp/tripline-live/');
}

const FORBIDDEN = [/[A-Za-z]:(?:\\\\|\\|\/)+Users/, /AppData/, /AQ\.Ab8/, /AIza[0-9A-Za-z_-]{20,}/, /\bDELL\b/];
/** Throw if the text still contains a Windows user path or something shaped like an API key. */
export function assertClean(text: string): void {
  for (const re of FORBIDDEN) if (re.test(text)) throw new Error(`refusing to write: ${re} still matches`);
}
