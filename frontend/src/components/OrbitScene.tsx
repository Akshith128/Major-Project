import { useEffect, useRef } from 'react';
import * as THREE from 'three';
import type { Theme } from '../lib/theme';

/**
 * Hero centrepiece: a black hole with a lime accretion disk, a photon ring, a
 * lensed arc of the disk's far side, tilted orbits with five agent lights, and a
 * starfield. It centres itself on the hero's [data-orbit-anchor] stage and is
 * sized so every orbit stays inside that stage, clear of the copy below it.
 * The pointer turns the system slightly; scrolling carries it up with the page,
 * tips the disk edge-on and fades it out. Both themes have their own palette.
 * Under reduced motion it renders still frames only.
 */

type Palette = {
  disk: THREE.Color;
  hot: THREE.Color;
  halo: THREE.Color;
  orbit: THREE.Color;
  orbitOpacity: number;
  agent: THREE.Color;
  glow: THREE.Color;
  stars: THREE.Color;
  starOpacity: number;
  light: boolean;
};

const PALETTES: Record<Theme, Palette> = {
  dark: {
    disk: new THREE.Color('#6FF218'),
    hot: new THREE.Color('#F0FFDC'),
    halo: new THREE.Color('#8CFF3A'),
    orbit: new THREE.Color('#6FF218'),
    orbitOpacity: 0.2,
    agent: new THREE.Color('#E4FFC8'),
    glow: new THREE.Color('#6FF218'),
    stars: new THREE.Color('#FFFFFF'),
    starOpacity: 0.75,
    light: false,
  },
  light: {
    disk: new THREE.Color('#3E9A00'),
    hot: new THREE.Color('#0B2A00'),
    halo: new THREE.Color('#2E7D00'),
    orbit: new THREE.Color('#2E7D00'),
    orbitOpacity: 0.28,
    agent: new THREE.Color('#1F5C00'),
    glow: new THREE.Color('#5BC80F'),
    stars: new THREE.Color('#1A2416'),
    starOpacity: 0.28,
    light: true,
  },
};

const DISK_INNER = 1.3;
const DISK_OUTER = 5.4;
const ORBITS = [5.9, 6.7, 7.5, 8.3, 9.1];
const TILT_X = -1.22;
const TILT_Z = 0.14;
// The orbits lie flatter than the disk, so they stay low and wide around it.
const ORBIT_TILT_X = -1.38;
const ORBIT_TILT_Z = 0.06;
// How far the pointer can turn the system about its horizontal axis.
const POINTER_TILT = 0.08;

const vertex = /* glsl */ `
  varying vec2 vUv;
  varying vec3 vPos;
  void main() {
    vUv = uv;
    vPos = position;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

// Swirling plasma: hottest at the inner edge, dissolving at the outer edge, one
// side brighter (Doppler beaming). Dark theme adds light; light theme lays ink.
const diskFragment = /* glsl */ `
  uniform float uTime;
  uniform vec3 uColor;
  uniform vec3 uHot;
  uniform float uInner;
  uniform float uOuter;
  uniform float uLight;
  uniform float uFade;
  varying vec3 vPos;

  float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }
  float noise(vec2 p) {
    vec2 i = floor(p), f = fract(p);
    vec2 u = f * f * (3.0 - 2.0 * f);
    return mix(mix(hash(i), hash(i + vec2(1, 0)), u.x), mix(hash(i + vec2(0, 1)), hash(i + vec2(1, 1)), u.x), u.y);
  }
  float fbm(vec2 p) {
    float v = 0.0, a = 0.5;
    for (int i = 0; i < 5; i++) { v += a * noise(p); p *= 2.03; a *= 0.5; }
    return v;
  }

  void main() {
    float r = length(vPos.xy);
    float t = clamp((r - uInner) / (uOuter - uInner), 0.0, 1.0);
    float angle = atan(vPos.y, vPos.x);
    float swirl = angle + uTime * (0.9 / (0.3 + t)) + 2.4 * log(r);
    float streaks = fbm(vec2(swirl * 2.6, r * 3.0));
    float fine = fbm(vec2(swirl * 10.0, r * 12.0));
    float body = pow(1.0 - t, 1.7) * (0.5 + 0.85 * streaks) + 0.3 * fine * (1.0 - t);
    float beaming = 0.6 + 0.6 * sin(angle + 0.6);
    float innerEdge = smoothstep(0.0, 0.04, t);
    float outerEdge = 1.0 - smoothstep(0.5, 1.0, t);
    float a = clamp(body * beaming * innerEdge * outerEdge, 0.0, 1.0) * uFade;
    vec3 c = mix(uColor, uHot, pow(1.0 - t, 5.0));
    if (uLight > 0.5) gl_FragColor = vec4(c, min(1.0, a * 1.25));
    else gl_FragColor = vec4(c * a * 2.6, a);
  }
`;

// The photon ring: a thin bright ring hugging the horizon plus a wide soft glow.
const haloFragment = /* glsl */ `
  uniform vec3 uColor;
  uniform vec3 uHot;
  uniform float uTime;
  uniform float uLight;
  uniform float uFade;
  varying vec2 vUv;
  void main() {
    float r = length(vUv - 0.5) * 2.0;
    float ring = exp(-pow((r - 0.2) / 0.012, 2.0));
    float glow = exp(-pow((r - 0.2) / 0.09, 2.0)) * 0.55 + exp(-r * 4.0) * 0.25;
    float flicker = 0.93 + 0.07 * sin(uTime * 2.3);
    float a = clamp((ring * 1.3 + glow) * flicker, 0.0, 1.0) * (1.0 - smoothstep(0.7, 1.0, r)) * uFade;
    vec3 c = mix(uColor, uHot, ring * 0.7);
    if (uLight > 0.5) gl_FragColor = vec4(c, a * 0.85);
    else gl_FragColor = vec4(c * a * 1.8, a);
  }
`;

function webglAvailable(): boolean {
  try {
    const c = document.createElement('canvas');
    return !!(c.getContext('webgl2') || c.getContext('webgl'));
  } catch {
    return false;
  }
}

export function OrbitScene({ theme }: { theme: Theme }) {
  const host = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = host.current;
    if (!el || !webglAvailable()) return;
    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
    const p = PALETTES[theme];
    const blending = p.light ? THREE.NormalBlending : THREE.AdditiveBlending;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x000000, 0);
    el.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    // A long lens keeps the near side of the orbits from ballooning toward the copy.
    const camera = new THREE.PerspectiveCamera(24, 1, 0.1, 400);
    camera.position.set(0, 0, 30);

    const system = new THREE.Group();
    scene.add(system);
    const tilt = new THREE.Group();
    tilt.rotation.set(TILT_X, 0, TILT_Z);
    system.add(tilt);
    const orbitPlane = new THREE.Group();
    orbitPlane.rotation.set(ORBIT_TILT_X, 0, ORBIT_TILT_Z);
    system.add(orbitPlane);

    const fade = { value: 1 };

    // Event horizon: an opaque sphere that hides the far side of the disk.
    const horizon = new THREE.Mesh(new THREE.SphereGeometry(1, 64, 64), new THREE.MeshBasicMaterial({ color: 0x000000 }));
    system.add(horizon);

    const diskUniforms = {
      uTime: { value: 0 },
      uColor: { value: p.disk },
      uHot: { value: p.hot },
      uInner: { value: DISK_INNER },
      uOuter: { value: DISK_OUTER },
      uLight: { value: p.light ? 1 : 0 },
      uFade: fade,
    };
    const diskMaterial = new THREE.ShaderMaterial({
      uniforms: diskUniforms,
      vertexShader: vertex,
      fragmentShader: diskFragment,
      transparent: true,
      depthWrite: false,
      blending,
      side: THREE.DoubleSide,
    });
    const disk = new THREE.Mesh(new THREE.RingGeometry(DISK_INNER, DISK_OUTER, 256, 8), diskMaterial);
    tilt.add(disk);

    // Lensed image of the disk's far side, bent up and over the horizon.
    const lensed = new THREE.Mesh(new THREE.RingGeometry(DISK_INNER, DISK_OUTER, 256, 8), diskMaterial);
    lensed.scale.setScalar(0.5);
    lensed.rotation.set(-TILT_X - 0.1, 0, 0);
    tilt.add(lensed);

    const haloUniforms = { uTime: { value: 0 }, uColor: { value: p.halo }, uHot: { value: p.hot }, uLight: { value: p.light ? 1 : 0 }, uFade: fade };
    const halo = new THREE.Mesh(
      new THREE.PlaneGeometry(11, 11),
      new THREE.ShaderMaterial({ uniforms: haloUniforms, vertexShader: vertex, fragmentShader: haloFragment, transparent: true, depthWrite: false, blending }),
    );
    halo.renderOrder = -1;
    system.add(halo);

    // Orbits, each carrying one agent light.
    const agents: { dot: THREE.Mesh; radius: number; speed: number; phase: number }[] = [];
    const orbitMaterial = new THREE.LineBasicMaterial({ color: p.orbit, transparent: true, opacity: p.orbitOpacity, depthWrite: false });
    const dotGeometry = new THREE.SphereGeometry(0.07, 16, 16);
    const dotMaterial = new THREE.MeshBasicMaterial({ color: p.agent, transparent: true });
    const glowTexture = makeGlowTexture();
    const glowMaterial = new THREE.SpriteMaterial({ map: glowTexture, color: p.glow, transparent: true, depthWrite: false, blending, opacity: p.light ? 0.55 : 1 });
    ORBITS.forEach((radius, i) => {
      const points = new THREE.EllipseCurve(0, 0, radius, radius).getPoints(256);
      orbitPlane.add(new THREE.LineLoop(new THREE.BufferGeometry().setFromPoints(points), orbitMaterial));
      const dot = new THREE.Mesh(dotGeometry, dotMaterial);
      const glow = new THREE.Sprite(glowMaterial);
      glow.scale.setScalar(0.8);
      dot.add(glow);
      orbitPlane.add(dot);
      agents.push({ dot, radius, speed: 0.24 / Math.sqrt(radius / 6), phase: i * 1.37 });
    });

    // Starfield on a distant shell.
    const starCount = 1800;
    const positions = new Float32Array(starCount * 3);
    for (let i = 0; i < starCount; i++) {
      const v = new THREE.Vector3().randomDirection().multiplyScalar(60 + Math.random() * 120);
      positions.set([v.x, v.y, v.z], i * 3);
    }
    const starGeometry = new THREE.BufferGeometry();
    starGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    const starMaterial = new THREE.PointsMaterial({ color: p.stars, size: 0.35, sizeAttenuation: true, transparent: true, opacity: p.starOpacity, depthWrite: false });
    const stars = new THREE.Points(starGeometry, starMaterial);
    scene.add(stars);

    const pointer = { x: 0, y: 0, tx: 0, ty: 0 };
    const onPointer = (e: PointerEvent) => {
      pointer.tx = (e.clientX / window.innerWidth) * 2 - 1;
      pointer.ty = (e.clientY / window.innerHeight) * 2 - 1;
    };
    window.addEventListener('pointermove', onPointer, { passive: true });

    // Layout: where the stage is on the page (at scroll 0), in world units.
    let height = 1;
    let worldPerPx = 0;
    let baseScale = 1;
    const resize = () => {
      const width = el.clientWidth;
      height = el.clientHeight || 1;
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      const visibleH = 2 * Math.tan(THREE.MathUtils.degToRad(camera.fov / 2)) * camera.position.z;
      worldPerPx = visibleH / height;
      const anchor = document.querySelector('[data-orbit-anchor]')?.getBoundingClientRect();
      if (anchor && anchor.height > 0) {
        const cx = anchor.left + anchor.width / 2;
        const cy = anchor.top + window.scrollY + anchor.height / 2;
        system.position.set((cx - width / 2) * worldPerPx, -(cy - height / 2) * worldPerPx, 0);
        // Fit the outer orbit (with its agent glow) and the disk inside the stage, as the camera
        // actually sees them; on narrow screens the disk's width caps the size instead.
        const stageHalf = (anchor.height / 2) * worldPerPx;
        const stageHalfWidth = (anchor.width / 2) * worldPerPx;
        baseScale = Math.min(fitScale(system.position.y, stageHalf, camera.position.z), (stageHalfWidth * 1.6) / DISK_OUTER);
      } else {
        system.position.set(0, 0, 0);
        baseScale = 0.8;
      }
    };
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(el);
    const anchorEl = document.querySelector('[data-orbit-anchor]');
    if (anchorEl) observer.observe(anchorEl);

    const clock = new THREE.Clock();
    let frame = 0;

    const draw = () => {
      const t = reduced ? 6 : clock.getElapsedTime();
      const progress = Math.min(1, window.scrollY / Math.max(1, window.innerHeight * 0.8));

      // The system scrolls with the page, so it never slides under the copy.
      camera.position.y = -window.scrollY * worldPerPx;
      camera.lookAt(0, camera.position.y, 0);

      pointer.x += (pointer.tx - pointer.x) * 0.05;
      pointer.y += (pointer.ty - pointer.y) * 0.05;
      system.rotation.set(pointer.y * POINTER_TILT, pointer.x * 0.14, 0);
      system.scale.setScalar(baseScale);
      tilt.rotation.x = TILT_X - progress * 0.3;
      orbitPlane.rotation.x = ORBIT_TILT_X - progress * 0.15;
      fade.value = 1 - progress;
      orbitMaterial.opacity = p.orbitOpacity * (1 - progress);
      dotMaterial.opacity = 1 - progress;
      glowMaterial.opacity = (p.light ? 0.55 : 1) * (1 - progress);

      diskUniforms.uTime.value = t;
      haloUniforms.uTime.value = t;
      halo.quaternion.copy(camera.quaternion);
      for (const a of agents) {
        const angle = a.phase + t * a.speed;
        a.dot.position.set(Math.cos(angle) * a.radius, Math.sin(angle) * a.radius, 0);
      }
      stars.rotation.y = t * 0.004;
      stars.position.y = camera.position.y;
      renderer.render(scene, camera);
    };

    const loop = () => {
      if (window.scrollY < window.innerHeight) draw();
      frame = requestAnimationFrame(loop);
    };

    if (reduced) {
      draw();
      window.addEventListener('scroll', draw, { passive: true });
    } else {
      loop();
    }

    const onVisibility = () => {
      if (reduced) return;
      cancelAnimationFrame(frame);
      if (!document.hidden) loop();
    };
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      window.removeEventListener('pointermove', onPointer);
      window.removeEventListener('scroll', draw);
      document.removeEventListener('visibilitychange', onVisibility);
      scene.traverse((obj) => {
        const mesh = obj as THREE.Mesh;
        mesh.geometry?.dispose();
        const material = mesh.material as THREE.Material | THREE.Material[] | undefined;
        if (Array.isArray(material)) material.forEach((m) => m.dispose());
        else material?.dispose();
      });
      glowTexture.dispose();
      renderer.dispose();
      renderer.domElement.remove();
    };
  }, [theme]);

  return <div ref={host} className="aegis-orbit-scene pointer-events-none fixed inset-0 -z-10" aria-hidden="true" />;
}

/**
 * The largest scale at which the outer orbit (plus agent glow) and the disk, seen in
 * perspective from `distance` and turned by the pointer either way, stay within
 * `half` world units above and below `centerY`.
 */
function fitScale(centerY: number, half: number, distance: number): number {
  const shapes: { radius: number; tiltX: number; tiltZ: number; margin: number }[] = [
    { radius: ORBITS[ORBITS.length - 1], tiltX: ORBIT_TILT_X, tiltZ: ORBIT_TILT_Z, margin: 0.45 },
    { radius: DISK_OUTER * 0.85, tiltX: TILT_X, tiltZ: TILT_Z, margin: 0 },
  ];
  const v = new THREE.Vector3();
  const fits = (scale: number) =>
    shapes.every(({ radius, tiltX, tiltZ, margin }) =>
      [-POINTER_TILT, POINTER_TILT].every((pointer) => {
        const rotation = new THREE.Euler(pointer, 0, 0);
        const plane = new THREE.Euler(tiltX, 0, tiltZ);
        for (let i = 0; i < 96; i++) {
          const a = (i / 96) * Math.PI * 2;
          v.set(Math.cos(a) * radius, Math.sin(a) * radius, 0).applyEuler(plane).applyEuler(rotation).multiplyScalar(scale);
          const depth = distance / (distance - v.z);
          const y = (centerY + v.y) * depth - centerY;
          if (Math.abs(y) + margin * scale * depth > half) return false;
        }
        return true;
      }),
    );
  let lo = 0.1;
  let hi = 4;
  for (let i = 0; i < 24; i++) {
    const mid = (lo + hi) / 2;
    if (fits(mid)) lo = mid;
    else hi = mid;
  }
  return lo;
}

function makeGlowTexture(): THREE.Texture {
  const size = 64;
  const canvas = document.createElement('canvas');
  canvas.width = canvas.height = size;
  const ctx = canvas.getContext('2d')!;
  const g = ctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2);
  g.addColorStop(0, 'rgba(255,255,255,1)');
  g.addColorStop(0.3, 'rgba(255,255,255,0.35)');
  g.addColorStop(1, 'rgba(255,255,255,0)');
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, size, size);
  return new THREE.CanvasTexture(canvas);
}
