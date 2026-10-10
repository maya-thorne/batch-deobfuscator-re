# 📋 Worker 2 액티브 태스크 체크리스트 (batch-deobfuscator-re)

## 📌 6대 필수 품질 과업 완료 현황

- [x] **1. 실제 깃허브 웹페이지 접속 및 인간 관점 UI/UX 실측 검증**:
  - Chrome CDP(포트 9227) 격리 탭으로 `https://github.com/maya-thorne/batch-deobfuscator-re` 접속 완료.
  - Live DOM 실측: `banner`(823x219px), `architecture`(823x340px), `terminalDemo`(823x358px) 100% 가시성 및 렌더링 검증 완료.
  - CLI 사용법(`python -m deobfuscator`, `batch-deobfuscator`), 설치 가이드, 배너 및 다이어그램 가독성 실측 검증 완료.
  - 모든 이미지는 클릭 시 raw 미디어 뷰어로 튕기지 않도록 `<a href="...">` 래핑 유지 완료.
  - 실측 스크린샷 보관: `Assets_스크린샷/batch_deobfuscator_re_final_screenshot.png`, `batch_deobfuscator_re_release_screenshot.png`.

- [x] **2. 10개국어 다국어 네비게이션 및 시각 자료 현지화**:
  - 10개국어 문서(`docs/locales/{en,ko,zh-CN,es,hi,ar,pt-BR,ru,fr,id}.md`) 링크 100% 정상 작동 검증.
  - CLI 사용 예시, 옵션 플래그 설명, 탈난독화 파이프라인 다이어그램의 레이블을 해당 언어로 현지화 완료.
  - 언어별 배너 10종 및 아키텍처 다이어그램 10종(`docs/assets/locales/<lang>/*.svg`) 1:1 매핑 및 XML 유효성 검증 완료.

- [x] **3. 시각적 에셋(CLI 터미널 GIF / 파이프라인 SVG) 고도화**:
  - `batch-deobfuscator` CLI 실행 화면을 보여주는 애니메이션 터미널 SVG 에셋(`docs/assets/demo_terminal.svg`) 제작 완료.
  - Multi-pass 아키텍처 다이어그램(정규화 ➔ 테이블 치환 ➔ 샌드박스 ➔ 복원) SVG 10개 언어별 현지화 완료.

- [x] **4. GitHub 공식 Release 및 Git Tag (`v1.0.0`) 발행**:
  - `v1.0.0` 태그 생성 및 원격 푸시 완료.
  - GitHub REST API를 통해 공식 Release `v1.0.0: Multi-Pass Batch Deobfuscator Engine & Ghidra PE Forensics Archive` 등록 완료.
  - README 최신 Release 뱃지 연동 완료.

- [x] **5. 라이선스(LICENSE) 규격화 및 오픈소스 크레딧**:
  - 공식 LICENSE (MIT) 완비.
  - README 및 10개국어 문서 하단에 Mandiant, Unit 42, CCCS, DissectMalware 등 48+ 오픈소스 레퍼런스 원저작권 크레딧 테이블 구축 완료.

- [x] **6. 전역 규칙 준수 (AI 도구명/워터마크 0건)**:
  - 코드, CLI 도움말 출력, 주석, 문서 어디에도 AI 도구명이나 워터마크가 들어가지 않도록 전수 감사 통과.
  - 엔지니어 브랜딩 `Maya Thorne` 일관성 유지.

---

## 🛠️ 실전 CLI 패키지 (`deobfuscator`) 구축 완료
- 패키지 모듈: `deobfuscator/` (`__init__.py`, `__main__.py`, `cli.py`, `core.py`, `normalizers.py`, `diff.py`)
- 진입점: `python -m deobfuscator input.bat` 및 `batch-deobfuscator input.bat`
- 표준 패키징: `pyproject.toml` (PEP 517/621 규격)
- 플래그: `-o`, `-p/--passes`, `-d/--diff`, `--format {text,json}`, `-v/--verbose`, `--version`
- 단위/통합 테스트: `tests/test_cli.py` (6개 테스트 전수 통과) + `tests/test_suite.py` (4개 테스트 전수 통과)
