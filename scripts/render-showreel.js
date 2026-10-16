const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { pathToFileURL } = require('node:url');
const { chromium } = require('@playwright/test');

const root = path.resolve(__dirname, '..');
const artifacts = path.join(root, 'artifacts');
const frames = path.join(artifacts, 'showreel-frames');
const fps = 30;
const duration = 30;
const frameCount = fps * duration;
const audioPath = path.join(artifacts, 'proxyking-showreel-audio.wav');
const outputPath = path.join(artifacts, 'Proxyking-Showreel-30s-Vertical.mp4');
const posterPath = path.join(artifacts, 'Proxyking-Showreel-Poster.png');

function writeAudio(filename) {
  const rate = 48000;
  const samples = duration * rate;
  const data = Buffer.alloc(samples * 4);
  let seed = 0x7f4a7c15;
  const random = () => ((seed = (seed * 1664525 + 1013904223) >>> 0) / 0xffffffff) * 2 - 1;
  const notes = [[55, 65.41, 82.41], [49, 61.74, 73.42], [43.65, 55, 65.41], [51.91, 65.41, 77.78]];
  const hits = [3.6, 6.6, 11.6, 16.1, 20.1, 24.1, 27.05];
  let lowNoise = 0;
  for (let i = 0; i < samples; i++) {
    const t = i / rate;
    const chord = notes[Math.floor(t / 4) % notes.length];
    let v = 0;
    for (let n = 0; n < chord.length; n++) v += Math.sin(Math.PI * 2 * chord[n] * t + n * 1.7) * (0.055 / (n + 1));
    v += Math.sin(Math.PI * 2 * chord[0] * 2 * t) * 0.03 * (0.55 + 0.45 * Math.sin(Math.PI * 4 * t));
    const beat = t % 0.5;
    if (beat < 0.16) v += Math.sin(Math.PI * 2 * (58 + 80 * Math.exp(-beat * 35)) * beat) * Math.exp(-beat * 22) * 0.48;
    const snare = (t + 0.5) % 1;
    lowNoise = lowNoise * 0.72 + random() * 0.28;
    if (snare < 0.13) v += (random() * 0.7 + lowNoise * 0.3) * Math.exp(-snare * 28) * 0.22;
    const hat = t % 0.25;
    if (hat < 0.045) v += (random() - lowNoise) * Math.exp(-hat * 90) * 0.075;
    for (const hit of hits) {
      const d = t - hit;
      if (d > -0.48 && d < 0) v += (random() - lowNoise) * Math.pow((d + 0.48) / 0.48, 2) * 0.055;
      if (d >= 0 && d < 0.5) v += Math.sin(Math.PI * 2 * (105 - d * 90) * d) * Math.exp(-d * 8) * 0.22;
    }
    const intro = Math.min(1, t / 0.8);
    const outro = Math.min(1, (duration - t) / 1.4);
    v *= intro * outro;
    const pan = Math.sin(t * 0.37) * 0.12;
    const left = Math.max(-1, Math.min(1, v * (1 - pan)));
    const right = Math.max(-1, Math.min(1, v * (1 + pan)));
    data.writeInt16LE(Math.round(left * 32767), i * 4);
    data.writeInt16LE(Math.round(right * 32767), i * 4 + 2);
  }
  const header = Buffer.alloc(44);
  header.write('RIFF', 0); header.writeUInt32LE(36 + data.length, 4); header.write('WAVE', 8);
  header.write('fmt ', 12); header.writeUInt32LE(16, 16); header.writeUInt16LE(1, 20); header.writeUInt16LE(2, 22);
  header.writeUInt32LE(rate, 24); header.writeUInt32LE(rate * 4, 28); header.writeUInt16LE(4, 32); header.writeUInt16LE(16, 34);
  header.write('data', 36); header.writeUInt32LE(data.length, 40);
  fs.writeFileSync(filename, Buffer.concat([header, data]));
}

(async () => {
  fs.mkdirSync(artifacts, { recursive: true });
  fs.rmSync(frames, { recursive: true, force: true });
  fs.mkdirSync(frames, { recursive: true });
  const chromePaths = [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
  ];
  const executablePath = chromePaths.find(candidate => fs.existsSync(candidate));
  const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) });
  const page = await browser.newPage({ viewport: { width: 720, height: 1280 }, deviceScaleFactor: 1 });
  await page.goto(pathToFileURL(path.join(root, 'showreel', 'showreel.html')).href);
  await page.evaluate(() => window.__ready);
  const stage = page.locator('#stage');
  for (let frame = 0; frame < frameCount; frame++) {
    await page.evaluate(({ frame, fps }) => window.renderFrame(frame, fps), { frame, fps });
    await stage.screenshot({ path: path.join(frames, `frame-${String(frame).padStart(4, '0')}.png`) });
    if (frame % 90 === 0) process.stdout.write(`Rendered ${Math.round(frame / frameCount * 100)}%\n`);
  }
  await page.evaluate(({ frame, fps }) => window.renderFrame(frame, fps), { frame: 875, fps });
  await stage.screenshot({ path: posterPath });
  await browser.close();
  writeAudio(audioPath);
  const ffmpeg = spawnSync('ffmpeg', [
    '-y', '-framerate', String(fps), '-i', path.join(frames, 'frame-%04d.png'), '-i', audioPath,
    '-vf', 'scale=1080:1920:flags=lanczos,format=yuv420p', '-c:v', 'libx264', '-preset', 'medium', '-crf', '17',
    '-c:a', 'aac', '-b:a', '192k', '-movflags', '+faststart', '-t', String(duration), outputPath
  ], { stdio: 'inherit' });
  if (ffmpeg.status !== 0) throw new Error(`ffmpeg exited with ${ffmpeg.status}`);
  fs.rmSync(frames, { recursive: true, force: true });
  console.log(`Created ${outputPath}`);
})().catch(error => { console.error(error); process.exitCode = 1; });
