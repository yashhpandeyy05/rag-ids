/* GradientASCII - Vanilla JS WebGL2 Implementation from React Bits */
(function(global) {
  'use strict';

  const MAX_COLORS = 8;
  const MAX_CLICKS = 4;
  const MAX_TRAIL = 24;
  const CLICK_LIFE = 1.2;
  const TRAIL_LIFE = 0.7;
  const TRAIL_STEP = 0.015;
  const INTRO_SECONDS = 2.4;
  const ATLAS_CELL_W = 60;
  const ATLAS_CELL_H = 100;
  const ATLAS_COLUMNS = 16;
  const FONT_SCALE = 0.78;
  const DEFAULT_COLORS = ['#1e3fd8', '#f6f8ff', '#a5d8ff', '#38bdf8'];
  const DEFAULT_CHARACTERS = ' =+xX0S8#@';
  const DEFAULT_FONT = '"Geist Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
  const SHAPES = { horizon: 0, pinch: 1, rise: 2, eclipse: 3 };
  const CLICK_EFFECTS = { none: 0, wave: 1, burst: 2 };

  const VERTEX = `#version 300 es
  out vec2 vUv;
  void main() {
    vec2 p = vec2(float((gl_VertexID << 1) & 2), float(gl_VertexID & 2));
    vUv = p;
    gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);
  }`;

  const COMMON = `
  float hash12(vec2 p) {
    vec3 q = fract(vec3(p.xyx) * 0.1031);
    q += dot(q, q.yzx + 33.33);
    return fract((q.x + q.y) * q.z);
  }
  `;

  const FIELD = `#version 300 es
  precision highp float;
  precision highp int;
  uniform float uAspect;
  uniform float uTime;
  uniform int uShape;
  uniform vec3 uRamp[8];
  uniform int uCount;
  uniform float uScale;
  uniform float uSoftness;
  uniform float uFlow;
  uniform vec2 uSeed;
  uniform vec4 uTrail[24];
  uniform float uRadius;
  uniform vec4 uClicks[4];
  uniform int uClickEffect;
  uniform float uIntro;
  uniform float uFrame;
  in vec2 vUv;
  layout(location = 0) out vec4 outColor;
  layout(location = 1) out vec4 outAux;
  ${COMMON}
  vec2 hash22(vec2 p) {
    vec3 q = fract(vec3(p.xyx) * vec3(0.1031, 0.103, 0.0973));
    q += dot(q, q.yzx + 33.33);
    return fract((q.xx + q.yz) * q.zy) * 2.0 - 1.0;
  }

  float noise(vec2 p) {
    vec2 i = floor(p);
    vec2 f = fract(p);
    vec2 u = f * f * f * (f * (f * 6.0 - 15.0) + 10.0);
    float a = dot(hash22(i), f);
    float b = dot(hash22(i + vec2(1.0, 0.0)), f - vec2(1.0, 0.0));
    float c = dot(hash22(i + vec2(0.0, 1.0)), f - vec2(0.0, 1.0));
    float d = dot(hash22(i + vec2(1.0, 1.0)), f - vec2(1.0, 1.0));
    return 0.5 + 0.5 * mix(mix(a, b, u.x), mix(c, d, u.x), u.y);
  }

  vec3 labToRgb(vec3 lab) {
    float l = lab.x + 0.3963377774 * lab.y + 0.2158037573 * lab.z;
    float m = lab.x - 0.1055613458 * lab.y - 0.0638541728 * lab.z;
    float s = lab.x - 0.0894841775 * lab.y - 1.2914855480 * lab.z;
    l = l * l * l;
    m = m * m * m;
    s = s * s * s;
    return vec3(
      4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
      -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
      -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s
    );
  }

  vec3 encode(vec3 c) {
    c = clamp(c, 0.0, 1.0);
    return mix(c * 12.92, 1.055 * pow(c, vec3(1.0 / 2.4)) - 0.055, step(0.0031308, c));
  }

  vec3 horizon(vec2 p, float time, out float order) {
    float span = 0.5 * max(uAspect, 1.0);
    float x = p.x / span;
    float arch = -0.17 - 0.2 * x * x + 0.02 * sin(time * 0.6);
    float soft = mix(0.05, 0.22, uSoftness);
    float edge = p.y - arch;
    float rim = 0.38 * smoothstep(-soft, 0.42, edge);
    vec2 sun = vec2(0.08 * sin(time * 0.31) * span, 0.58);
    float spread = length((p - sun) / vec2(0.95 * span, 0.75));
    float sky = mix(0.55, 1.0, smoothstep(0.2, 0.95, spread));
    order = clamp(edge * 1.3, 0.0, 1.0);
    return vec3(rim, sky, smoothstep(0.18, 0.62, edge));
  }

  vec3 pinch(vec2 p, float time, out float order) {
    float span = 0.5 * max(uAspect, 0.75);
    float x = p.x / span;
    float sway = 0.02 * sin(x * 1.7 + time * 0.55);
    float breathe = 1.0 + 0.06 * sin(time * 0.8);
    float width = (0.13 + 0.22 * x * x) * breathe * mix(0.85, 1.2, uSoftness);
    float y = abs(p.y - sway) / width;
    float t = exp(-pow(y, 2.2)) * (0.42 + 0.58 * exp(-x * x * 1.8));
    order = clamp(abs(p.y - sway) * 2.4 + abs(x) * 0.3, 0.0, 1.0);
    return vec3(t, t, 0.0);
  }

  vec3 rise(vec2 p, float time, out float order) {
    float wide = max(uAspect, 0.9);
    vec2 center = vec2(0.05 * sin(time * 0.45) * wide, -0.7);
    vec2 radius = vec2(0.82 * wide, 0.64 * (1.0 + 0.04 * sin(time * 0.8)));
    float d = length((p - center) / radius);
    float soft = mix(0.6, 1.15, uSoftness);
    float t = clamp(pow(clamp(1.0 - d, 0.0, 1.0), soft) * 1.35, 0.0, 1.0);
    order = clamp((d - 0.2) * 1.3, 0.0, 1.0);
    return vec3(t, t, 0.0);
  }

  vec3 eclipse(vec2 p, float time, out float order) {
    float fit = min(1.0, uAspect * 1.25);
    float r = 0.23 * fit * (1.0 + 0.015 * sin(time * 0.9));
    float angle = atan(p.y, p.x);
    float rays = noise(vec2(cos(angle), sin(angle)) * 2.2 + time * 0.08) * 0.8 + 0.6;
    float d = length(p) - r;
    float reach = mix(0.07, 0.15, uSoftness) * rays * fit;
    float t = smoothstep(-0.006, 0.006 + 0.02 * uSoftness, d) * exp(-max(d, 0.0) / reach);
    order = clamp(d * 2.0, 0.0, 1.0);
    return vec3(t, t, 0.0);
  }

  vec4 tone(float t, vec3 ramp[8], int count) {
    float x = smoothstep(0.3, 1.0, t) * float(count - 1);
    int index = int(floor(x));
    return vec4(mix(ramp[index], ramp[min(index + 1, count - 1)], fract(x)), smoothstep(0.0, 0.38, t));
  }

  void main() {
    vec2 p = (vUv - 0.5) * vec2(uAspect, 1.0);
    float time = uTime;
    vec2 q = p / uScale;
    vec2 warp = vec2(
      noise(q * 1.6 + uSeed + vec2(0.0, time * 0.3)),
      noise(q * 1.6 + uSeed.yx + vec2(4.3, -time * 0.24))
    ) - 0.5;
    q += warp * uFlow * (uShape == 3 ? 0.04 : 0.18);
    float order = 0.0;
    vec3 shape;
    if (uShape == 0) shape = horizon(q, time, order);
    else if (uShape == 1) shape = pinch(q, time, order);
    else if (uShape == 2) shape = rise(q, time, order);
    else shape = eclipse(q, time, order);

    float reveal = clamp((uIntro * 1.45 - order) / 0.45, 0.0, 1.0);
    reveal = reveal * reveal * (3.0 - 2.0 * reveal);

    float scramble = 0.0;
    for (int i = 0; i < 24; i++) {
      vec4 point = uTrail[i];
      if (point.z <= 0.0) continue;
      vec2 d = p - point.xy;
      scramble = max(scramble, point.z * exp(-dot(d, d) / (uRadius * uRadius)));
    }
    for (int i = 0; i < 4; i++) {
      vec4 c = uClicks[i];
      if (c.w <= 0.0) continue;
      float d = length(p - c.xy);
      if (uClickEffect == 1) {
        scramble = max(scramble, exp(-pow((d - c.z * 0.75) / 0.06, 2.0)) * c.w);
      } else if (uClickEffect == 2) {
        float size = 0.08 + 0.22 * (1.0 - exp(-c.z * 5.0));
        scramble = max(scramble, (1.0 - smoothstep(size * 0.6, size, d)) * c.w);
      }
    }
    vec2 t = clamp(shape.xy * mix(0.7, 1.0, reveal), 0.0, 1.0);
    vec4 mixed = mix(tone(t.x, uRamp, uCount), tone(t.y, uRamp, uCount), shape.z);
    vec3 color = encode(labToRgb(mixed.rgb));
    float alpha = mixed.a * reveal;
    float dither = (hash12(gl_FragCoord.xy + uFrame * 13.7) - 0.5) / 255.0;
    outColor = clamp(vec4(color * alpha + dither, alpha + dither), 0.0, 1.0);
    outAux = vec4(reveal, scramble, 0.0, 1.0);
  }`;

  const GLYPHS = `
  uniform sampler2D uField;
  uniform sampler2D uAux;
  uniform sampler2D uAtlas;
  uniform vec2 uResolution;
  uniform vec2 uCell;
  uniform vec2 uOffset;
  uniform vec2 uAtlasGrid;
  uniform float uCount;
  uniform float uDensity;
  uniform float uOpacity;
  uniform float uFlicker;
  uniform float uDepth;
  uniform float uGlyphTime;
  uniform float uSeedValue;
  uniform float uLight;
  ${COMMON}
  float sampleGlyph(float index, vec2 local, vec2 coord, float soft) {
    float column = mod(index, uAtlasGrid.x);
    float row = floor(index / uAtlasGrid.x);
    vec2 atlasUv = vec2((column + local.x) / uAtlasGrid.x, (row + 1.0 - local.y) / uAtlasGrid.y);
    vec2 continuous = coord / uAtlasGrid;
    float scale = exp2(soft);
    return textureGrad(uAtlas, atlasUv, dFdx(continuous) * scale, dFdy(continuous) * scale).a;
  }

  vec4 glyphAt(vec2 px) {
    vec2 coord = (px - uOffset) / uCell;
    vec2 cell = floor(coord);
    vec2 local = coord - cell;
    vec2 uv = clamp(((cell + 0.5) * uCell + uOffset) / uResolution, vec2(0.0), vec2(1.0));
    vec4 field = texture(uField, uv);
    vec4 aux = texture(uAux, uv);
    vec3 visible = uLight > 0.5 ? field.rgb + (1.0 - field.a) : field.rgb;
    float luma = dot(visible, vec3(0.2126, 0.7152, 0.0722));
    float value = uLight > 0.5 ? clamp((1.0 - luma) * 1.5, 0.0, 1.0) : luma;
    float pick = hash12(cell + uSeedValue * 7.31);
    float level = hash12(cell * 1.73 + 4.1 + uSeedValue);
    float tick = floor(uGlyphTime * 9.0 + level * 9.0);
    float wobble = (hash12(cell * 2.31 + tick * 17.7) - 0.5) * uFlicker * 0.4 + (level - 0.5) * 0.1;
    float tone = clamp(pow(value, 0.75) + wobble, 0.0, 1.0);
    float index = floor(tone * (uCount - 1.0) + 0.5);
    float decode = max(aux.g, 1.0 - aux.r);
    if (decode > 0.02) {
      float frame = floor(uGlyphTime * 20.0);
      if (hash12(cell * 3.7 + frame * 5.3) < decode * 1.25) index = 1.0 + floor(hash12(cell + frame * 1.37) * (uCount - 1.0));
    }
    float present = step(pick, uDensity * mix(1.0, 0.3 + tone * 1.1, 0.55));
    float cutoff = smoothstep(0.03, 0.1, value);
    float focus = step(hash12(cell * 0.71 + 9.2 + uSeedValue), uDepth);
    float coverage = sampleGlyph(index, local, coord, focus * 1.2);
    float alpha = uOpacity * present * cutoff * coverage * mix(1.0, 0.35 + 0.65 * level, 0.55) * (1.0 - focus * 0.5);
    if (uLight < 0.5) {
      vec3 light = field.rgb * 0.55 + vec3(0.03) * field.a;
      return vec4(light * alpha, 0.6 * field.a * alpha);
    }
    vec3 ink = visible * 0.8;
    return vec4(ink * alpha, alpha);
  }
  `;

  const HALO = `#version 300 es
  precision highp float;
  uniform float uDownscale;
  in vec2 vUv;
  out vec4 outColor;
  ${GLYPHS}
  void main() {
    outColor = glyphAt(gl_FragCoord.xy * uDownscale);
  }`;

  const BLUR = `#version 300 es
  precision highp float;
  uniform sampler2D uSource;
  uniform vec2 uStep;
  in vec2 vUv;
  out vec4 outColor;
  void main() {
    vec4 sum = texture(uSource, vUv) * 0.2270270270;
    sum += texture(uSource, vUv + uStep * 1.3846153846) * 0.3162162162;
    sum += texture(uSource, vUv - uStep * 1.3846153846) * 0.3162162162;
    sum += texture(uSource, vUv + uStep * 3.2307692308) * 0.0702702703;
    sum += texture(uSource, vUv - uStep * 3.2307692308) * 0.0702702703;
    outColor = sum;
  }`;

  const COMPOSITE = `#version 300 es
  precision highp float;
  uniform sampler2D uHalo;
  uniform float uGlow;
  uniform float uGradient;
  uniform float uGrain;
  uniform float uFrame;
  in vec2 vUv;
  out vec4 outColor;
  ${GLYPHS}
  void main() {
    vec4 base = texture(uField, vUv) * uGradient;
    vec4 glyph = glyphAt(gl_FragCoord.xy);
    vec4 halo = texture(uHalo, vUv) * uGlow;
    vec4 color;
    if (uLight < 0.5) {
      color = base + glyph + halo;
    } else {
      color = glyph + base * (1.0 - glyph.a);
      color += halo * 0.6 * (1.0 - color.a);
    }
    float grain = (hash12(gl_FragCoord.xy + uFrame * vec2(17.0, 59.0)) + hash12(gl_FragCoord.xy * 1.31 + uFrame * 7.0) - 1.0) * uGrain;
    float body = clamp(color.a, 0.0, 1.0);
    color.rgb += grain * (0.25 + body) * 0.5;
    color.a = clamp(color.a, 0.0, 1.0);
    color.rgb = clamp(color.rgb, 0.0, color.a);
    outColor = color;
  }`;

  const clamp = (value, min, max) => Math.min(max, Math.max(min, value));
  const toLinear = value => (value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);

  const toLab = ([r, g, b]) => {
    const lr = toLinear(r);
    const lg = toLinear(g);
    const lb = toLinear(b);
    const l = Math.cbrt(0.4122214708 * lr + 0.5363325363 * lg + 0.0514459929 * lb);
    const m = Math.cbrt(0.2119034982 * lr + 0.6806995451 * lg + 0.1073969566 * lb);
    const s = Math.cbrt(0.0883024619 * lr + 0.2817188376 * lg + 0.6299787005 * lb);
    return [
      0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s,
      1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
      0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s
    ];
  };

  const compile = (gl, type, source) => {
    const shader = gl.createShader(type);
    if (!shader) return null;
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (gl.getShaderParameter(shader, gl.COMPILE_STATUS)) return shader;
    gl.deleteShader(shader);
    return null;
  };

  const link = (gl, fragmentSource) => {
    const vertex = compile(gl, gl.VERTEX_SHADER, VERTEX);
    const fragment = compile(gl, gl.FRAGMENT_SHADER, fragmentSource);
    const program = gl.createProgram();
    if (!vertex || !fragment || !program) return null;
    gl.attachShader(program, vertex);
    gl.attachShader(program, fragment);
    gl.linkProgram(program);
    gl.deleteShader(vertex);
    gl.deleteShader(fragment);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      gl.deleteProgram(program);
      return null;
    }
    const uniforms = {};
    const count = gl.getProgramParameter(program, gl.ACTIVE_UNIFORMS);
    for (let i = 0; i < count; i++) {
      const info = gl.getActiveUniform(program, i);
      if (!info) continue;
      const name = info.name.replace(/\[0\]$/, '');
      uniforms[name] = gl.getUniformLocation(program, name);
    }
    return { program, uniforms };
  };

  const createTarget = (gl, count) => {
    const textures = Array.from({ length: count }, () => {
      const texture = gl.createTexture();
      gl.bindTexture(gl.TEXTURE_2D, texture);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
      return texture;
    });
    return { textures, framebuffer: gl.createFramebuffer(), width: 0, height: 0 };
  };

  const sizeTarget = (gl, target, width, height) => {
    if (target.width === width && target.height === height) return;
    target.width = width;
    target.height = height;
    gl.bindFramebuffer(gl.FRAMEBUFFER, target.framebuffer);
    target.textures.forEach((texture, i) => {
      gl.bindTexture(gl.TEXTURE_2D, texture);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA8, width, height, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
      gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0 + i, gl.TEXTURE_2D, texture, 0);
    });
    gl.bindFramebuffer(gl.FRAMEBUFFER, null);
  };

  const buildAtlas = (gl, characters, fontFamily) => {
    const list = [...new Set([...characters].filter(char => char !== '\n' && char !== '\r'))];
    if (!list.length) list.push(' ');
    const font = `300 ${Math.round(ATLAS_CELL_H * FONT_SCALE)}px ${fontFamily}`;
    const columns = Math.min(ATLAS_COLUMNS, list.length);
    const rows = Math.ceil(list.length / columns);
    const canvas = document.createElement('canvas');
    canvas.width = ATLAS_CELL_W * columns;
    canvas.height = ATLAS_CELL_H * rows;
    const context = canvas.getContext('2d');
    if (context) {
      context.font = font;
      context.textAlign = 'center';
      context.textBaseline = 'middle';
      context.fillStyle = '#fff';
      list.forEach((char, index) => {
        const column = index % columns;
        const row = Math.floor(index / columns);
        context.fillText(char, column * ATLAS_CELL_W + ATLAS_CELL_W / 2, row * ATLAS_CELL_H + ATLAS_CELL_H / 2 + 3);
      });
    }
    const texture = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, texture);
    gl.pixelStorei(gl.UNPACK_PREMULTIPLY_ALPHA_WEBGL, false);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA8, gl.RGBA, gl.UNSIGNED_BYTE, canvas);
    gl.generateMipmap(gl.TEXTURE_2D);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR_MIPMAP_LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    return { texture, count: list.length, grid: [columns, rows] };
  };

  class GradientASCIIInstance {
    constructor(container, options = {}) {
      this.container = container;
      this.canvas = document.createElement('canvas');
      this.canvas.className = 'gradient-ascii-canvas';
      this.container.appendChild(this.canvas);

      const palette = (Array.isArray(options.colors) && options.colors.length ? options.colors : DEFAULT_COLORS).slice(0, MAX_COLORS);
      this.settings = {
        colors: palette.length > 1 ? palette : [palette[0], palette[0]],
        shape: SHAPES[options.shape] ?? 0,
        characters: options.characters || DEFAULT_CHARACTERS,
        cellSize: clamp(options.cellSize ?? 18, 6, 64),
        density: clamp(options.density ?? 0.8, 0, 1),
        glyphOpacity: clamp(options.glyphOpacity ?? 0.85, 0, 1),
        glow: clamp(options.glow ?? 0.2, 0, 2),
        depthOfField: clamp(options.depthOfField ?? 0, 0, 1),
        flicker: clamp(options.flicker ?? 0.2, 0, 1),
        softness: clamp(options.softness ?? 0.5, 0, 1),
        scale: clamp(options.scale ?? 1, 0.4, 2.5),
        flow: clamp(options.flow ?? 0.5, 0, 2),
        speed: Math.max(0, options.speed ?? 1),
        gradientOpacity: clamp(options.gradientOpacity ?? 0.9, 0, 1),
        grain: clamp(options.grain ?? 0.08, 0, 0.4),
        variation: Math.max(0, options.variation ?? 0),
        mouseInteraction: options.mouseInteraction !== false,
        scrambleRadius: clamp(options.scrambleRadius ?? 0.1, 0.02, 0.4),
        clickEffect: CLICK_EFFECTS[options.clickEffect] ?? 1,
        intro: options.intro !== false,
        lightMode: !!options.lightMode,
        fontFamily: options.fontFamily || DEFAULT_FONT,
        dpr: options.dpr
      };

      this.init();
    }

    init() {
      const gl = this.canvas.getContext('webgl2', {
        alpha: true,
        premultipliedAlpha: true,
        antialias: false,
        depth: false,
        stencil: false
      });
      if (!gl) return;
      this.gl = gl;

      this.field = link(gl, FIELD);
      this.halo = link(gl, HALO);
      this.blur = link(gl, BLUR);
      this.composite = link(gl, COMPOSITE);
      if (!this.field || !this.halo || !this.blur || !this.composite) return;

      this.vao = gl.createVertexArray();
      this.fieldTarget = createTarget(gl, 2);
      this.haloA = createTarget(gl, 1);
      this.haloB = createTarget(gl, 1);

      this.probe = document.createElement('canvas').getContext('2d', { willReadFrequently: true });
      this.colorCache = new Map();

      this.reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
      this.view = { width: 1, height: 1, ratio: 1 };
      this.ramp = new Float32Array(MAX_COLORS * 3);
      this.clickData = new Float32Array(MAX_CLICKS * 4);
      this.clicks = [];
      this.trailData = new Float32Array(MAX_TRAIL * 4);
      this.trail = [];
      this.pointer = { x: 0, y: 0, inside: false };
      this.atlas = null;
      this.atlasKey = '';
      this.paletteKey = '';
      this.time = 0;
      this.glyphTime = 0;
      this.introClock = this.settings.intro && !this.reduce ? 0 : 1;
      this.frameSeed = 0;
      this.grainClock = 0;
      this.raf = 0;
      this.last = 0;
      this.visible = true;
      this.disposed = false;

      this.setupListeners();
      this.resize();
    }

    parse(value) {
      const key = String(value);
      const cached = this.colorCache.get(key);
      if (cached) return cached;
      let rgb = [0, 0, 0];
      if (this.probe) {
        this.probe.clearRect(0, 0, 1, 1);
        this.probe.fillStyle = '#000000';
        this.probe.fillStyle = key;
        this.probe.fillRect(0, 0, 1, 1);
        const [r, g, b] = this.probe.getImageData(0, 0, 1, 1).data;
        rgb = [r / 255, g / 255, b / 255];
      }
      this.colorCache.set(key, rgb);
      return rgb;
    }

    syncAtlas() {
      const s = this.settings;
      const key = `${s.fontFamily}|${s.characters}`;
      if (key === this.atlasKey && this.atlas) return;
      this.atlasKey = key;
      if (this.atlas) this.gl.deleteTexture(this.atlas.texture);
      this.atlas = buildAtlas(this.gl, s.characters, s.fontFamily);
      document.fonts?.load?.(`300 64px ${s.fontFamily}`, s.characters).then(() => {
        if (this.disposed || this.atlasKey !== key) return;
        if (this.atlas) this.gl.deleteTexture(this.atlas.texture);
        this.atlas = buildAtlas(this.gl, s.characters, s.fontFamily);
        this.draw();
      }, () => {});
    }

    syncPalette() {
      const s = this.settings;
      const key = s.colors.join(',');
      if (key === this.paletteKey) return;
      this.paletteKey = key;
      s.colors.forEach((color, i) => this.ramp.set(toLab(this.parse(color)), i * 3));
    }

    bindGlyphs(program, width, height) {
      if (!this.atlas) return;
      const s = this.settings;
      const u = program.uniforms;
      const cellH = s.cellSize * this.view.ratio;
      const cellW = cellH * (ATLAS_CELL_W / ATLAS_CELL_H);
      this.gl.activeTexture(this.gl.TEXTURE0);
      this.gl.bindTexture(this.gl.TEXTURE_2D, this.fieldTarget.textures[0]);
      this.gl.uniform1i(u.uField, 0);
      this.gl.activeTexture(this.gl.TEXTURE1);
      this.gl.bindTexture(this.gl.TEXTURE_2D, this.fieldTarget.textures[1]);
      this.gl.uniform1i(u.uAux, 1);
      this.gl.activeTexture(this.gl.TEXTURE2);
      this.gl.bindTexture(this.gl.TEXTURE_2D, this.atlas.texture);
      this.gl.uniform1i(u.uAtlas, 2);
      this.gl.uniform2f(u.uResolution, width, height);
      this.gl.uniform2f(u.uCell, cellW, cellH);
      this.gl.uniform2f(
        u.uOffset,
        (width - Math.ceil(width / cellW) * cellW) / 2,
        (height - Math.ceil(height / cellH) * cellH) / 2
      );
      this.gl.uniform2f(u.uAtlasGrid, this.atlas.grid[0], this.atlas.grid[1]);
      this.gl.uniform1f(u.uCount, this.atlas.count);
      this.gl.uniform1f(u.uDensity, s.density);
      this.gl.uniform1f(u.uOpacity, s.glyphOpacity);
      this.gl.uniform1f(u.uFlicker, this.reduce ? 0 : s.flicker);
      this.gl.uniform1f(u.uDepth, s.depthOfField);
      this.gl.uniform1f(u.uGlyphTime, this.glyphTime);
      this.gl.uniform1f(u.uSeedValue, s.variation);
      this.gl.uniform1f(u.uLight, s.lightMode ? 1 : 0);
    }

    draw() {
      const s = this.settings;
      const gl = this.gl;
      const aspect = this.view.width / this.view.height;
      this.syncAtlas();
      this.syncPalette();
      gl.bindVertexArray(this.vao);
      gl.disable(gl.BLEND);

      gl.bindFramebuffer(gl.FRAMEBUFFER, this.fieldTarget.framebuffer);
      gl.drawBuffers([gl.COLOR_ATTACHMENT0, gl.COLOR_ATTACHMENT1]);
      gl.viewport(0, 0, this.fieldTarget.width, this.fieldTarget.height);
      gl.useProgram(this.field.program);
      const fu = this.field.uniforms;
      gl.uniform1f(fu.uAspect, aspect);
      gl.uniform1f(fu.uTime, this.time);
      gl.uniform1i(fu.uShape, s.shape);
      gl.uniform3fv(fu.uRamp, this.ramp);
      gl.uniform1i(fu.uCount, s.colors.length);
      gl.uniform1f(fu.uScale, s.scale);
      gl.uniform1f(fu.uSoftness, s.softness);
      gl.uniform1f(fu.uFlow, s.flow);
      gl.uniform2f(fu.uSeed, s.variation * 3.17, s.variation * 1.91);
      gl.uniform4fv(fu.uTrail, this.trailData);
      gl.uniform1f(fu.uRadius, s.scrambleRadius);
      gl.uniform4fv(fu.uClicks, this.clickData);
      gl.uniform1i(fu.uClickEffect, s.clickEffect);
      gl.uniform1f(fu.uIntro, this.introClock);
      gl.uniform1f(fu.uFrame, this.frameSeed);
      gl.drawArrays(gl.TRIANGLES, 0, 3);

      const glowing = s.glow > 0.001;
      if (glowing) {
        gl.bindFramebuffer(gl.FRAMEBUFFER, this.haloA.framebuffer);
        gl.drawBuffers([gl.COLOR_ATTACHMENT0]);
        gl.viewport(0, 0, this.haloA.width, this.haloA.height);
        gl.useProgram(this.halo.program);
        this.bindGlyphs(this.halo, this.canvas.width, this.canvas.height);
        gl.uniform1f(this.halo.uniforms.uDownscale, this.canvas.width / this.haloA.width);
        gl.drawArrays(gl.TRIANGLES, 0, 3);

        gl.useProgram(this.blur.program);
        gl.activeTexture(gl.TEXTURE0);
        gl.uniform1i(this.blur.uniforms.uSource, 0);
        gl.bindFramebuffer(gl.FRAMEBUFFER, this.haloB.framebuffer);
        gl.bindTexture(gl.TEXTURE_2D, this.haloA.textures[0]);
        gl.uniform2f(this.blur.uniforms.uStep, 1 / this.haloA.width, 0);
        gl.drawArrays(gl.TRIANGLES, 0, 3);
        gl.bindFramebuffer(gl.FRAMEBUFFER, this.haloA.framebuffer);
        gl.bindTexture(gl.TEXTURE_2D, this.haloB.textures[0]);
        gl.uniform2f(this.blur.uniforms.uStep, 0, 1 / this.haloA.height);
        gl.drawArrays(gl.TRIANGLES, 0, 3);
      }

      gl.bindFramebuffer(gl.FRAMEBUFFER, null);
      gl.viewport(0, 0, this.canvas.width, this.canvas.height);
      gl.useProgram(this.composite.program);
      this.bindGlyphs(this.composite, this.canvas.width, this.canvas.height);
      const cu = this.composite.uniforms;
      gl.activeTexture(gl.TEXTURE3);
      gl.bindTexture(gl.TEXTURE_2D, this.haloA.textures[0]);
      gl.uniform1i(cu.uHalo, 3);
      gl.uniform1f(cu.uGlow, glowing ? s.glow : 0);
      gl.uniform1f(cu.uGradient, s.gradientOpacity);
      gl.uniform1f(cu.uGrain, s.grain);
      gl.uniform1f(cu.uFrame, this.frameSeed);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    }

    resize() {
      const s = this.settings;
      this.view.width = Math.max(1, this.container.clientWidth);
      this.view.height = Math.max(1, this.container.clientHeight);
      this.view.ratio = Math.min(s.dpr || window.devicePixelRatio || 1, 2);
      this.canvas.width = Math.max(1, Math.round(this.view.width * this.view.ratio));
      this.canvas.height = Math.max(1, Math.round(this.view.height * this.view.ratio));
      sizeTarget(
        this.gl,
        this.fieldTarget,
        Math.max(1, Math.round(this.canvas.width / 2)),
        Math.max(1, Math.round(this.canvas.height / 2))
      );
      const haloWidth = Math.max(1, Math.round(this.canvas.width / 4));
      const haloHeight = Math.max(1, Math.round(this.canvas.height / 4));
      sizeTarget(this.gl, this.haloA, haloWidth, haloHeight);
      sizeTarget(this.gl, this.haloB, haloWidth, haloHeight);
      this.draw();
      this.wake();
    }

    updateInput(dt) {
      this.trail.forEach(point => { point.age += dt; });
      while (this.trail.length && this.trail[this.trail.length - 1].age > TRAIL_LIFE) this.trail.pop();
      for (let i = 0; i < MAX_TRAIL; i++) {
        const point = this.trail[i];
        if (!point) {
          this.trailData[i * 4 + 2] = 0;
          continue;
        }
        const k = 1 - point.age / TRAIL_LIFE;
        this.trailData.set([point.x, point.y, k * k, 0], i * 4);
      }
      this.clicks.forEach(click => { click.age += dt; });
      while (this.clicks.length && this.clicks[this.clicks.length - 1].age > CLICK_LIFE) this.clicks.pop();
      for (let i = 0; i < MAX_CLICKS; i++) {
        const click = this.clicks[i];
        if (!click) {
          this.clickData[i * 4 + 3] = 0;
          continue;
        }
        const k = click.age / CLICK_LIFE;
        const envelope = Math.min(1, click.age / 0.08) * (1 - k) * (1 - k);
        this.clickData.set([click.x, click.y, click.age, envelope], i * 4);
      }
    }

    frame(now) {
      this.raf = 0;
      if (this.disposed || !this.visible || document.hidden) return;
      const s = this.settings;
      const dt = this.last ? clamp((now - this.last) / 1000, 0.001, 0.05) : 1 / 60;
      this.last = now;
      if (!this.reduce) {
        this.time += dt * s.speed * 0.5;
        this.glyphTime += dt * Math.max(s.speed, 0.15);
      }
      if (this.introClock < 1) this.introClock = Math.min(1, this.introClock + dt / INTRO_SECONDS);
      this.grainClock += dt;
      if (!this.reduce && this.grainClock > 1 / 24) {
        this.grainClock = 0;
        this.frameSeed = (this.frameSeed + 1) % 97;
      }
      this.updateInput(dt);
      this.draw();
      const busy = !this.reduce || this.introClock < 1 || this.clicks.length > 0 || this.trail.length > 0;
      if (busy) this.raf = requestAnimationFrame(t => this.frame(t));
      else this.last = 0;
    }

    wake() {
      if (this.container && this.container.clientWidth > 0 && this.container.clientHeight > 0) {
        this.visible = true;
      }
      if (!this.raf && !this.disposed && this.visible && !document.hidden) {
        this.raf = requestAnimationFrame(t => this.frame(t));
      }
    }

    update(options = {}) {
      if (options.lightMode !== undefined) this.settings.lightMode = !!options.lightMode;
      if (options.colors) {
        const palette = (Array.isArray(options.colors) && options.colors.length ? options.colors : DEFAULT_COLORS).slice(0, MAX_COLORS);
        this.settings.colors = palette.length > 1 ? palette : [palette[0], palette[0]];
        this.syncPalette();
      }
      this.draw();
      this.wake();
    }

    locate(event) {
      const rect = this.container.getBoundingClientRect();
      const x = (event.clientX - rect.left) / Math.max(1, rect.width);
      const y = 1 - (event.clientY - rect.top) / Math.max(1, rect.height);
      const aspect = rect.width / Math.max(1, rect.height);
      this.pointer.inside = x >= 0 && x <= 1 && y >= 0 && y <= 1;
      this.pointer.x = (x - 0.5) * aspect;
      this.pointer.y = y - 0.5;
    }

    setupListeners() {
      this.onPointerMove = event => {
        this.locate(event);
        const s = this.settings;
        if (!this.pointer.inside || !s.mouseInteraction || this.reduce) return;
        const head = this.trail[0];
        const gap = head ? Math.hypot(this.pointer.x - head.x, this.pointer.y - head.y) : Infinity;
        if (gap < TRAIL_STEP) return;
        if (head && head.age < 0.1) {
          const steps = Math.min(6, Math.floor(gap / (TRAIL_STEP * 2)));
          for (let i = 1; i <= steps; i++) {
            const k = i / (steps + 1);
            this.trail.unshift({ x: head.x + (this.pointer.x - head.x) * k, y: head.y + (this.pointer.y - head.y) * k, age: 0 });
          }
        }
        this.trail.unshift({ x: this.pointer.x, y: this.pointer.y, age: 0 });
        this.trail.length = Math.min(this.trail.length, MAX_TRAIL);
        this.wake();
      };

      this.onPointerDown = event => {
        this.locate(event);
        const s = this.settings;
        if (!this.pointer.inside || !s.clickEffect || this.reduce) return;
        this.clicks.unshift({ x: this.pointer.x, y: this.pointer.y, age: 0 });
        if (this.clicks.length > MAX_CLICKS) this.clicks.pop();
        this.wake();
      };

      this.onVisibility = () => {
        this.last = 0;
        this.wake();
      };

      this.resizeObserver = new ResizeObserver(() => this.resize());
      this.resizeObserver.observe(this.container);

      this.intersection = new IntersectionObserver(entries => {
        this.visible = entries.some(entry => entry.isIntersecting);
        if (this.visible) {
          this.last = 0;
          this.wake();
        }
      });
      this.intersection.observe(this.container);

      window.addEventListener('pointermove', this.onPointerMove, { passive: true });
      window.addEventListener('pointerdown', this.onPointerDown, { passive: true });
      document.addEventListener('visibilitychange', this.onVisibility);
    }

    destroy() {
      this.disposed = true;
      cancelAnimationFrame(this.raf);
      this.resizeObserver?.disconnect();
      this.intersection?.disconnect();
      window.removeEventListener('pointermove', this.onPointerMove);
      window.removeEventListener('pointerdown', this.onPointerDown);
      document.removeEventListener('visibilitychange', this.onVisibility);
      [this.fieldTarget, this.haloA, this.haloB].forEach(target => {
        target.textures.forEach(texture => this.gl.deleteTexture(texture));
        this.gl.deleteFramebuffer(target.framebuffer);
      });
      if (this.atlas) this.gl.deleteTexture(this.atlas.texture);
      this.gl.deleteVertexArray(this.vao);
      [this.field, this.halo, this.blur, this.composite].forEach(item => this.gl.deleteProgram(item.program));
      this.gl.getExtension('WEBGL_lose_context')?.loseContext();
      this.canvas.remove();
    }
  }

  global.GradientASCII = GradientASCIIInstance;
})(window);
