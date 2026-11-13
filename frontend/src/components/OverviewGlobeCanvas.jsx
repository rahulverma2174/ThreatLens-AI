import { Component, useEffect, useLayoutEffect, useMemo, useRef } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";
import * as THREE from "three";

const NODE_COLORS = {
  incident: "#fb6175",
  alert: "#ff9a60",
  ip: "#4bd3e9",
  user: "#548fff",
  event: "#a18cff",
};
const EDGE_COLORS = {
  failure: "#fb6175",
  alert: "#ff9a60",
  alert_evidence: "#ff9a60",
  incident_alert: "#a18cff",
  incident_evidence: "#a18cff",
  principal_event: "#548fff",
  observed_event: "#4bd3e9",
  success: "#51c99b",
};

function hashText(value) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

// Stable positions are a rendering aid only; they have no geographic meaning.
export function abstractPosition(id, radius = 2.035) {
  const first = hashText(id);
  const second = hashText(`${id}:angle`);
  const y = 1 - 2 * ((first % 1_000_003) / 1_000_003);
  const angle = (second % 1_000_003) / 1_000_003 * Math.PI * 2;
  const horizontal = Math.sqrt(Math.max(0, 1 - y * y));
  return new THREE.Vector3(Math.cos(angle) * horizontal * radius, y * radius, Math.sin(angle) * horizontal * radius);
}

function relationColor(kind) {
  return new THREE.Color(EDGE_COLORS[kind] ?? "#4bd3e9");
}

function RelationshipLines({ nodes, edges }) {
  const geometry = useMemo(() => {
    const positionsById = new Map(nodes.map((node) => [node.id, abstractPosition(node.id, 2.045)]));
    const positions = [];
    const colors = [];
    const segmentCount = 7;
    for (const edge of edges) {
      const start = positionsById.get(edge.source);
      const end = positionsById.get(edge.target);
      if (!start || !end) continue;
      const color = relationColor(edge.kind);
      let prior = start;
      for (let segment = 1; segment <= segmentCount; segment += 1) {
        const amount = segment / segmentCount;
        const point = start.clone().lerp(end, amount).normalize().multiplyScalar(2.045 + Math.sin(Math.PI * amount) * 0.055);
        positions.push(prior.x, prior.y, prior.z, point.x, point.y, point.z);
        colors.push(color.r, color.g, color.b, color.r, color.g, color.b);
        prior = point;
      }
    }
    const result = new THREE.BufferGeometry();
    result.setAttribute("position", new THREE.Float32BufferAttribute(positions, 3));
    result.setAttribute("color", new THREE.Float32BufferAttribute(colors, 3));
    return result;
  }, [nodes, edges]);

  return <lineSegments geometry={geometry}><lineBasicMaterial vertexColors transparent opacity={0.38} depthWrite={false} /></lineSegments>;
}

function AmbientParticles() {
  const geometry = useMemo(() => {
    const positions = [];
    for (let index = 0; index < 44; index += 1) {
      const seed = hashText(`ambient-particle-${index}`);
      const second = hashText(`ambient-particle-angle-${index}`);
      const vertical = 1 - 2 * ((seed % 1_000_003) / 1_000_003);
      const angle = (second % 1_000_003) / 1_000_003 * Math.PI * 2;
      const horizontal = Math.sqrt(Math.max(0, 1 - vertical * vertical));
      const radius = 2.34 + ((hashText(`ambient-radius-${index}`) % 1_000) / 1_000) * 0.52;
      positions.push(Math.cos(angle) * horizontal * radius, vertical * radius, Math.sin(angle) * horizontal * radius);
    }
    const result = new THREE.BufferGeometry();
    result.setAttribute("position", new THREE.Float32BufferAttribute(positions, 3));
    return result;
  }, []);

  return <points geometry={geometry}><pointsMaterial color="#70a6c7" size={0.018} transparent opacity={0.25} depthWrite={false} sizeAttenuation /></points>;
}

function EntityMarkers({ nodes, selectedId, hoveredId, onSelect, onHover }) {
  const markersRef = useRef(null);
  const positions = useMemo(() => nodes.map((node) => abstractPosition(node.id)), [nodes]);

  useLayoutEffect(() => {
    const markers = markersRef.current;
    if (!markers) return;
    const matrix = new THREE.Object3D();
    nodes.forEach((node, index) => {
      const active = node.id === selectedId || node.id === hoveredId;
      matrix.position.copy(positions[index]);
      matrix.scale.setScalar(active ? 1.75 : node.type === "incident" || node.type === "alert" ? 1.3 : 1);
      matrix.updateMatrix();
      markers.setMatrixAt(index, matrix.matrix);
      markers.setColorAt(index, new THREE.Color(active ? "#f5fdff" : NODE_COLORS[node.type] ?? "#4bd3e9"));
    });
    markers.instanceMatrix.needsUpdate = true;
    if (markers.instanceColor) markers.instanceColor.needsUpdate = true;
  }, [nodes, positions, selectedId, hoveredId]);

  return <instancedMesh ref={markersRef} args={[undefined, undefined, nodes.length]} onPointerMove={(event) => {
    event.stopPropagation();
    const node = nodes[event.instanceId];
    onHover(node?.id ?? null);
  }} onPointerOut={() => onHover(null)} onClick={(event) => {
    event.stopPropagation();
    const node = nodes[event.instanceId];
    if (node) onSelect(node.id);
  }}>
    <sphereGeometry args={[0.035, 8, 8]} />
    <meshStandardMaterial emissive="#122b45" emissiveIntensity={0.55} roughness={0.42} metalness={0.12} />
  </instancedMesh>;
}

function Scene({ nodes, edges, selectedId, hoveredId, onSelect, onHover, rotating, resetToken, reducedMotion }) {
  const { camera, gl, invalidate } = useThree();
  const controls = useMemo(() => new OrbitControls(camera, gl.domElement), [camera, gl]);

  useEffect(() => {
    controls.enableDamping = rotating && !reducedMotion;
    controls.dampingFactor = 0.06;
    controls.enablePan = false;
    controls.minDistance = 4.8;
    controls.maxDistance = 9;
    controls.autoRotate = rotating && !reducedMotion;
    controls.autoRotateSpeed = 0.34;
    const handleChange = () => invalidate();
    controls.addEventListener("change", handleChange);
    controls.update();
    return () => controls.removeEventListener("change", handleChange);
  }, [controls, invalidate, rotating, reducedMotion]);

  useEffect(() => () => controls.dispose(), [controls]);

  useEffect(() => {
    if (resetToken > 0) controls.reset();
  }, [controls, resetToken]);

  useFrame(() => controls.update());

  return <>
    <ambientLight intensity={0.72} />
    <directionalLight position={[4, 4, 5]} intensity={1.45} color="#c5efff" />
    <pointLight position={[-4, -2, -3]} intensity={0.55} color="#4d7aff" />
    <mesh>
      <sphereGeometry args={[2, 36, 28]} />
      <meshStandardMaterial color="#0b1629" roughness={0.86} metalness={0.14} emissive="#071427" emissiveIntensity={0.5} />
    </mesh>
    <mesh>
      <sphereGeometry args={[2.008, 24, 18]} />
      <meshBasicMaterial color="#235277" wireframe transparent opacity={0.2} depthWrite={false} />
    </mesh>
    <AmbientParticles />
    <RelationshipLines nodes={nodes} edges={edges} />
    <EntityMarkers nodes={nodes} selectedId={selectedId} hoveredId={hoveredId} onSelect={onSelect} onHover={onHover} />
  </>;
}

class GlobeErrorBoundary extends Component {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    return this.state.failed ? this.props.fallback : this.props.children;
  }
}

export default function OverviewGlobeCanvas(props) {
  return <GlobeErrorBoundary key={props.canvasRevision} fallback={props.fallback}>
    <Canvas frameloop={!props.visible ? "never" : props.rotating && !props.reducedMotion ? "always" : "demand"} dpr={[1, 1.35]} camera={{ position: [0, 0, 6.4], fov: 41 }} gl={{ antialias: false, alpha: true, powerPreference: "low-power" }} fallback={props.fallback}>
      <Scene {...props} />
    </Canvas>
  </GlobeErrorBoundary>;
}
