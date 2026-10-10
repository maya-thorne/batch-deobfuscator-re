# 🚫 Worker 2 중복 방지 규칙 (Anti-Patterns)

1. **이론 백서 중복 금지**:
   - `batch-deobfuscator-re`는 실전 CLI 도구이므로, 30년 역사나 장황한 기법 분류 백서를 나열하지 않는다. (해당 내용은 Worker 1의 `batch-obfuscation-research`에 위임)

2. **바이너리 역공학 중복 금지**:
   - Ghidra 역공학, PE 헤더 언패킹, 어셈블리 분석을 포함하지 않는다. (해당 기능은 Worker 5의 `bat2exe-ghidra-forensics`에 위임)

3. **탐지 룰셋 중복 금지**:
   - Sigma 규칙이나 YARA 룰을 자체 제작하여 저장소의 메인 피처로 삼지 않는다. (해당 기능은 Worker 3의 `batch-forensics-and-ghidra-re`에 위임)

4. **AST 컴파일러 이론 중복 금지**:
   - 복잡한 AST 파서 이론이나 오토마타 증명을 다루지 않는다. (해당 기능은 Worker 4의 `cmd-ast-deobfuscator`에 위임)
