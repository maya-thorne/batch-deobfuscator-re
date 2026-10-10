# 📦 수집된 배치 난독화 & 디옵퓨스케이션 오픈소스 레퍼런스 색인 (46대 도구 & AI 자산)

본 디렉터리는 Windows 배치 파일(Batch/CMD) 난독화, 디옵퓨스케이션, 분석 및 탐지에 관한 GitHub 정예 오픈소스 리포지토리 46종과 Hugging Face AI 데이터셋을 전수 클론 및 다운로드하여 보관한 아카이브입니다.

---

## 🗂️ 카테고리별 디렉토리 색인

### 1. ⚙️ 고급 및 마스터 난독화기 (Advanced Obfuscators)
- **`Invoke-DOSfuscation`**: Daniel Bohannon의 전설적인 CMD 난독화 프레임워크 (Black Hat 2018).
- **`Invoke-CradleCrafter`**: 다양한 다운로드 크래들 난독화 도구.
- **`Out-FINcodedCommand`**: FIN7 APT 그룹 스타일 명령 인코더.
- **`SomalifuscatorV2`**: KingKDot의 변수 스크램블링 및 안티-VM 배치 난독화기.
- **`0xidiz3r`**: 0xTas의 Rust 기반 배치 난독화 & 디옵퓨스케이터.
- **`Abobus-obfuscator` / `Abobus-obfuscator-EscaLag`**: 최신 변수 스크램블링 난독화기.
- **`BatchObfuscator-guillaC`**: Python 기반 문자열 분할 난독화기.
- **`BatchObfuscator-wirebits`**: 다중 인코딩 및 캐럿 난독화기.
- **`BatchObfuscator-EmenstaNougat`**: 다단계 변수 슬라이싱 난독화기.
- **`BatchObfuscator-BiggerDABOSS`**: 대규모 배치 난독화기.
- **`batch-obfuscator-SkyEmie`**: 교육용 클래식 환경변수 난독화기.
- **`batchobfuscator-baum1810` / `batchobfuscator`**: 경량 배치 난독화기.
- **`batobfuscate-machine1337`**: 머신러닝 회피형 배치 난독화기.
- **`Batch-Obfuscator-90th`**: 특수 문자 치환 난독화기.
- **`simple-batch-obfuscator` / `simple-batch-obfuscator-DavidNiessen`**: 배치/파워셸 래핑 패키저.
- **`PandaCrypter-chainski`**: 암호화 기반 배치/스크립트 크립터.
- **`batchalchemy`**: 파이프라인 배치 난독화기.
- **`BatCloak`**: BOM 주입 및 FUD 바이패스 엔진 연구 자료.

### 2. 🔓 디옵퓨스케이터 및 분석기 (Deobfuscators & Analyzers)
- **`batch_deobfuscator`**: DissectMalware의 파이썬 기반 환경변수 확장 및 파싱 도구.
- **`assemblyline-service-batchdeobfuscator` / `assemblyline-batchdeobfuscator`**: 캐나다 사이버안보센터(CCCS) 공식 배치 분석 파이프라인.
- **`Exorcism`**: KingKDot의 cmd.exe 런타임 DLL 후킹 디옵퓨스케이터.
- **`Batch-Dump`**: SwezyDev의 프로세스 모니터링 및 헥스 패턴 자동 제거 덤퍼.
- **`BatchDeobfuscator-CrowTheBest`**: set 명령어 역해석 디옵퓨스케이터.
- **`CMD-DeObfuscator` / `CMD-DeObfuscator-bobbystacksmash`**: 대화형 CMD 난독화 해제기.
- **`JSBatchDeobfuscator-yrotak`**: 자바스크립트 기반 배치 디옵퓨스케이터.
- **`batch-deobfuscator` / `batch-deobfuscator-hiroshil`**: 파이썬 경량 디옵퓨스케이션 스크립트.
- **`Remcos-Rat-Batch-Deobfuscator-fatihbeyexe`**: Remcos RAT 배치 드로퍼 전용 해독기.
- **`DBOBUS-tccontre`**: 문법 구문 트리(AST) 기반 배치 디옵퓨스케이터.
- **`DE-SomalifuscatorV2`**: Somalifuscator 전용 해독기.
- **`BatchShield-Decryptor`**: BatchShield 복호화기.
- **`batobfuscate-deobfuscator-936erpl`**: batobfuscate 전용 해독기.

### 3. 📦 Bat2Exe 변환기 및 패커 (Bat2Exe & Packers)
- **`Bat2Exe-dehoisted`**: C++ 스텁을 이용한 배치 ➔ EXE 변환기.
- **`BatchToApp-DosX-dev` / `BatchToApp-DosX`**: GUI 커스텀 지원 배치 앱 패커.
- **`bat2exe-123Studios`**: 배치 ➔ EXE 변환기.
- **`bat2exe-islamadel`**: 파이썬 기반 배치 컴파일러.
- **`bat2exe-Toon-arch`**: C++ 배치 래퍼.
- **`batFile-To-exe-Converter`**: 배치 파일 변환기.

### 4. 🤖 Hugging Face AI 모델 & 데이터셋 (`huggingface-ai-models/`)
- **`dessertlab_PSStrikes-commands.json` / `README.md`**: 공격 커맨드 라인 데이터셋.
- **`nsgood_mitre-attack-command-generation.json` / `README.md`**: MITRE ATT&CK 커맨드 생성 데이터셋.
- **`leachl_obfuscated-exebench.json`**: 난독화 벤치마크 데이터셋.
