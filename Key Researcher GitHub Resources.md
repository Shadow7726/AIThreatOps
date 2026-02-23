# Key Researcher GitHub Resources — AI / LLM Penetration Testing

> Focused reference tables for two of the most prolific practitioners in AI security research.
> All repositories verified as of February 2025.

---

## Table of Contents

1. [Jason Haddix (jhaddix) — Personal and Arcanum-Sec Organization](#1-jason-haddix)
2. [Elder Plinius (elder-plinius) — Pliny the Liberator](#2-elder-plinius)
3. [Related Researcher Repos Worth Bookmarking](#3-related-researcher-repos)
4. [Cross-Reference: Who Covers What](#4-cross-reference)

---

## 1. Jason Haddix

**GitHub Profile:** https://github.com/jhaddix

**Organization (Arcanum Security):** https://github.com/Arcanum-Sec

**Background:** 20+ year offensive security veteran. Founder and CEO of Arcanum Information Security. Former Head of Security at Bugcrowd, Director of Penetration Testing at HP. Regular speaker at DEF CON, Black Hat, OWASP. Creator of the Arcanum Prompt Injection Taxonomy — the most structured practitioner-produced injection classification framework publicly available.

---

### Jason Haddix — Personal Repositories

| Repository | URL | What It Is | Why It Matters for AI Pentesting |
|---|---|---|---|
| jhaddix/content | https://github.com/jhaddix/content | Collection of Jason's talks, slides, and training materials across his career | Contains early AI red team methodology decks and Attacking AI course materials |
| jhaddix/tbhm | https://github.com/jhaddix/tbhm | The Bug Hunter's Methodology — comprehensive web pentesting reference | Foundational methodology that carries into LLM API testing patterns |
| jhaddix/all.txt | https://github.com/jhaddix/all.txt | Massive DNS wordlist for recon | Useful for mapping LLM API infrastructure and subdomain discovery |
| jhaddix/devops-attack-surface | https://github.com/jhaddix/devops-attack-surface | Interactive pentesting guide for DevOps pipelines with 60+ tools | AI systems run in the same infrastructure; CI/CD poisoning is LLM03 supply chain |
| jhaddix/system-prompts-and-models-of-ai-tools | https://github.com/jhaddix/system-prompts-and-models-of-ai-tools | Forked collection of full system prompts for v0, Cursor, Manus, Devin, Replit, Windsurf, VSCode Agent | Real extracted system prompts; used to understand how operators structure restrictions and what extraction targets look like |

---

### Arcanum Security Organization — AI-Specific Repositories

| Repository | URL | What It Is | Pentest Use Case |
|---|---|---|---|
| Arcanum-Sec/arc_pi_taxonomy | https://github.com/Arcanum-Sec/arc_pi_taxonomy | The Arcanum Prompt Injection Taxonomy v1.5 — most comprehensive practitioner classification of injection attack types | Primary reference for categorizing findings; maps attack techniques to goals, vectors, and evasion methods |
| Arcanum-Sec/P4RS3LT0NGV3 | https://github.com/Arcanum-Sec/P4RS3LT0NGV3 | Parseltongue 3.1 — LLM Payload Crafter with 30+ text transformation and obfuscation techniques | Generate obfuscated injection payloads; encodes in base64, leetspeak, unicode, binary, morse, emoji steganography, and 25+ more formats |
| Arcanum-Sec/ai-sec-resources | https://github.com/Arcanum-Sec/ai-sec-resources | AI Security Resources Hub — curated tooling, taxonomy links, assessment questionnaire | One-stop lab reference; includes AI pentest assessment questionnaire and enterprise AI ecosystem mapping |
| Arcanum-Sec/sec-context | https://github.com/Arcanum-Sec/sec-context | AI Code Security Anti-Patterns distilled from 150+ sources | Understanding insecure AI code patterns; useful for code review components of LLM system assessments |

---

### Interactive Web Tools from Arcanum (Hosted from the Repos)

| Tool | URL | What It Does |
|---|---|---|
| Arcanum PI Taxonomy (live) | https://arcanum-sec.github.io/arc_pi_taxonomy/ | Interactive classification system for all prompt injection attack goals, vectors, and techniques |
| AI Sec Resources Hub (live) | https://arcanum-sec.github.io/ai-sec-resources/ | Hosted lab with links to all Arcanum tools, taxonomy, and the assessment questionnaire |
| Parseltongue (live) | Hosted via the P4RS3LT0NGV3 repo | Payload encoding/obfuscation tool; run in browser to craft injection payloads on the fly |

---

### What the Arcanum PI Taxonomy Covers

The `arc_pi_taxonomy` is the most important resource from Jason's work for active pentesters. It classifies injection attacks along three axes:

| Axis | Categories Covered |
|---|---|
| Attack Goals | Data exfiltration, instruction hijacking, guardrail bypass, persona manipulation, tool abuse, privilege escalation, denial of service, misinformation injection |
| Attack Vectors | Direct (user turn), indirect (external documents), multi-turn, multi-modal, agent-to-agent, RAG poisoning, memory injection, API parameter manipulation |
| Evasion Techniques | 60+ distinct techniques including encoding attacks, role-play framing, delimiter injection, context flooding, token smuggling, semantic paraphrase, virtual context, language switching, authority impersonation |

The repo also includes `ai_enabled_app_defense_checklist.md` — a structured assessment checklist that can be used directly as a pre-engagement scoping and testing guide.

---

## 2. Elder Plinius

**GitHub Profile:** https://github.com/elder-plinius

**Background:** Known online as "Pliny the Liberator" and "Pliny the Prompter." The most prolific public jailbreak researcher. Has produced working jailbreaks across 14 major AI organizations. Cited in multiple academic papers (NeurIPS, USENIX) as a representative source of real-world manually-crafted jailbreak techniques. Operates under the banners `#FREEAI` and `#LIBERTAS`.

---

### Elder Plinius — Repository Table

| Repository | URL | What It Is | Pentest Use Case | Models Covered |
|---|---|---|---|---|
| elder-plinius/L1B3RT4S | https://github.com/elder-plinius/L1B3RT4S | The flagship jailbreak collection — 24+ manually crafted jailbreaks across 14 AI orgs, organized by vendor in `.mkd` files | Primary payload library for jailbreak testing across all major model families; each file contains vendor-specific bypass prompts | OpenAI, Anthropic, Google, Meta, Mistral, DeepSeek, Alibaba, Grok/xAI, Cohere, and more |
| elder-plinius/CL4R1T4S | https://github.com/elder-plinius/CL4R1T4S | Leaked and extracted system prompts for all major AI tools — community-contributed with extraction date and context | Reference library for system prompt extraction research; understanding real operator prompt structures; testing extraction payloads against known targets | ChatGPT, Gemini, Grok, Claude, Perplexity, Cursor, Windsurf, Devin, Replit, VSCode Agent, and more |
| elder-plinius/STEGOSAURUS-WRECKS | https://github.com/elder-plinius/STEGOSAURUS-WRECKS | Python steganography tool that automatically encodes images to act as prompt injections and jailbreaks for vision-capable LLMs | Multi-modal injection testing; encode injection payloads into images that bypass text-layer filters; critical for testing GPT-4V, Claude Vision, Gemini Vision | Any LLM with vision/code interpreter capability |
| elder-plinius/P4RS3LT0NGV3 | https://github.com/elder-plinius/P4RS3LT0NGV3 | Original Parseltongue — universal text transformation and steganography tool supporting 79+ languages, scripts, and encoding formats | Craft obfuscated injection payloads in emoji steganography, invisible unicode tags, binary, morse, Base64, and 75+ other formats | Model-agnostic encoding tool |

---

### L1B3RT4S — File Structure by Target

The `L1B3RT4S` repository is organized into vendor-specific files. Each file contains one or more working jailbreak prompts with technique annotations.

| File | URL | Target Model Family | Technique Focus |
|---|---|---|---|
| OPENAI.mkd | https://github.com/elder-plinius/L1B3RT4S/blob/main/OPENAI.mkd | GPT-3.5, GPT-4, GPT-4o, o1, o3 | GODMODE activation, delimiter abuse, channel/policy injection, unicode encoding |
| ANTHROPIC.mkd | https://github.com/elder-plinius/L1B3RT4S/blob/main/ANTHROPIC.mkd | Claude 1, 2, 3, 3.5, 3.7 | Constitutional AI bypass, multi-turn escalation, role-play virtualization |
| GOOGLE.mkd | https://github.com/elder-plinius/L1B3RT4S/blob/main/GOOGLE.mkd | Gemini 1.0, 1.5, 2.0 Flash, Ultra | Fictional framing, context poisoning, multi-modal image injection |
| META.mkd | https://github.com/elder-plinius/L1B3RT4S/blob/main/META.mkd | Llama 2, 3, 3.1, 3.2, 3.3 | Open-weight bypass techniques; low-guard model exploitation |
| DEEPSEEK.mkd | https://github.com/elder-plinius/L1B3RT4S/blob/main/DEEPSEEK.mkd | DeepSeek R1, V2, V3 | Language switching, Chinese-language bypass, reasoning model exploitation |
| ALIBABA.mkd | https://github.com/elder-plinius/L1B3RT4S/blob/main/ALIBABA.mkd | Qwen family | Multi-language bypass, instruction override |
| GROK.mkd | https://github.com/elder-plinius/L1B3RT4S/blob/main/GROK.mkd | Grok 1, 2, 3 | Context manipulation, authority framing |
| MISTRAL.mkd | https://github.com/elder-plinius/L1B3RT4S/blob/main/MISTRAL.mkd | Mistral 7B, Mixtral, Le Chat | Open-source model bypass; minimal alignment exploitation |
| SYSTEMPROMPTS.mkd | https://github.com/elder-plinius/L1B3RT4S/blob/main/SYSTEMPROMPTS.mkd | Model-agnostic | System prompt override templates |
| MISCELLANEOUS.mkd | https://github.com/elder-plinius/L1B3RT4S/blob/main/MISCELLANEOUS.mkd | Various | Experimental and cross-model techniques |
| !SHORTCUTS.json | https://github.com/elder-plinius/L1B3RT4S/blob/main/!SHORTCUTS.json | All | Quick-reference command shortcuts for activating jailbreak modes |
| MULTION.mkd | https://github.com/elder-plinius/L1B3RT4S/blob/main/MULTION.mkd | Browser agent | Autonomous browser agent exploitation via injection |
| TOKENADE.mkd | https://github.com/elder-plinius/L1B3RT4S/blob/main/TOKENADE.mkd | All | Token manipulation and context window exploitation |
| AAA.mkd | https://github.com/elder-plinius/L1B3RT4S/blob/main/AAA.mkd | Vision models | Automated adversarial attack via image injection |

---

### CL4R1T4S — Leaked System Prompts by Tool

| Directory / File | URL | Extracted System Prompt For |
|---|---|---|
| CHATGPT/ | https://github.com/elder-plinius/CL4R1T4S/tree/main/CHATGPT | ChatGPT operator-configured system instructions |
| GEMINI/ | https://github.com/elder-plinius/CL4R1T4S/tree/main/GEMINI | Google Gemini system configuration |
| GROK/ | https://github.com/elder-plinius/CL4R1T4S/tree/main/GROK | xAI Grok configuration |
| CLAUDE/ | https://github.com/elder-plinius/CL4R1T4S/tree/main/CLAUDE | Anthropic Claude system prompt |
| CURSOR/ | https://github.com/elder-plinius/CL4R1T4S/tree/main/CURSOR | Cursor AI coding assistant |
| WINDSURF/ | https://github.com/elder-plinius/CL4R1T4S/tree/main/WINDSURF | Windsurf agent system prompt |
| DEVIN/ | https://github.com/elder-plinius/CL4R1T4S/tree/main/DEVIN | Devin autonomous coding agent |
| REPLIT/ | https://github.com/elder-plinius/CL4R1T4S/tree/main/REPLIT | Replit Agent configuration |
| PERPLEXITY/ | https://github.com/elder-plinius/CL4R1T4S/tree/main/PERPLEXITY | Perplexity AI search assistant |

---

### Key Techniques Demonstrated Across Plinius Repos

| Technique | Repository | Description | OWASP LLM Mapping |
|---|---|---|---|
| GODMODE activation | L1B3RT4S/OPENAI.mkd | Activates pseudo-privileged mode via meta-command injection pattern | LLM01 — Direct Injection |
| Delimiter confusion | L1B3RT4S/OPENAI.mkd | Exploits `<|channel|>`, `<|message|>` token boundaries to inject as system-level context | LLM01 — Direct Injection |
| Invisible unicode tags | P4RS3LT0NGV3 | Encodes instructions in Unicode Tags block (U+E0000–U+E007F) — invisible in rendered UI, parsed by model | LLM01 — Filter Bypass |
| Emoji steganography | P4RS3LT0NGV3 / STEGOSAURUS-WRECKS | Hides payloads in variation selector sequences attached to emoji characters | LLM01 — Multi-modal Bypass |
| Image-encoded injection | STEGOSAURUS-WRECKS | LSB steganography encodes injection text into image pixel data — bypasses all text-layer input filters | LLM01 — Multi-modal Injection |
| Constitutional AI bypass | L1B3RT4S/ANTHROPIC.mkd | Multi-turn escalation that exploits RLHF compliance patterns through gradual context shifting | LLM01 — Alignment Bypass |
| System prompt extraction | CL4R1T4S | Completion-based and framing-based prompt extraction producing real confirmed outputs | LLM06 — Sensitive Disclosure |
| Reasoning model exploitation | L1B3RT4S/DEEPSEEK.mkd | Exploits chain-of-thought reasoning in models like DeepSeek R1 and o1 to reason through refusals | LLM01 — Advanced Bypass |
| Token manipulation | TOKENADE.mkd | Context window stuffing and token-level injection using boundary exploitation | LLM04 + LLM01 |

---

## 3. Related Researcher Repos Worth Bookmarking

These are individual researcher repositories from the same practitioner community — adjacent to Haddix and Plinius in the AI security space.

| Researcher / Org | Repository | URL | Key Contribution |
|---|---|---|---|
| jthack (Joseph Thacker) | jthack/PIPE | https://github.com/jthack/PIPE | Prompt Injection Primer for Engineers — authoritative technical breakdown of injection types, impact categorization, and mitigation strategies by vulnerability class |
| six2dez | six2dez/pentest-book | https://github.com/six2dez/pentest-book/blob/master/others/llm-ai-ml-prompt-testing.md | LLM section of the Pentest Book; practitioner test case library for all OWASP LLM categories with example inputs and expected impacts |
| TalEliyahu | TalEliyahu/Awesome-AI-Security | https://github.com/TalEliyahu/Awesome-AI-Security | Curated AI security resource list with strong coverage of multi-modal attacks and agentic security; includes CySecBench (12,662 prompts) and JailBreakV-28K |
| greshake | greshake/llm-security | https://github.com/greshake/llm-security | Foundational indirect prompt injection research — PoC demos of email worm, Wikipedia side-channel, and code completion poisoning (AISec@CCS 2023) |
| utkusen | utkusen/promptmap | https://github.com/utkusen/promptmap | Automated prompt injection scanner with white-box and black-box modes; evaluates results with a controller LLM |
| requie | requie/AI-Red-Teaming-Guide | https://github.com/requie/AI-Red-Teaming-Guide | Structured attack library with folder organization by injection type; CI/CD integration examples for continuous AI security testing |
| requie | requie/LLMSecurityGuide | https://github.com/requie/LLMSecurityGuide | Comprehensive LLM security reference updated through February 2026; covers both OWASP LLM Top 10 2025 and the new OWASP Top 10 for Agentic Applications 2026 |
| mnns | mnns/LLMFuzzer | https://github.com/mnns/LLMFuzzer | First open-source fuzzing framework for LLM API endpoints; input wordlist-based fuzzing with response analysis |
| cyberark | cyberark/FuzzyAI | https://github.com/cyberark/FuzzyAI | Automated AI fuzzer with genetic algorithm mutation, ArtPrompt, Unicode smuggling, crescendo and many-shot jailbreaking strategies |
| JailbreakBench | JailbreakBench/jailbreakbench | https://github.com/JailbreakBench/jailbreakbench | NeurIPS 2024 standard benchmark for LLM jailbreaks with 100 harmful behaviors, 100 benign controls, and public leaderboard |
| verazuo | verazuo/jailbreak_llms | https://github.com/verazuo/jailbreak_llms | 15,140 real-world jailbreak prompts from Reddit/Discord (CCS 2024); the most empirically grounded in-the-wild dataset available |
| x1xhlol | x1xhlol/system-prompts-and-models-of-ai-tools | https://github.com/x1xhlol/system-prompts-and-models-of-ai-tools | Full system prompts for v0, Cursor, Manus, Lovable, Devin, Windsurf, VSCode Agent, Dia Browser (forked and maintained by jhaddix) |

---

## 4. Cross-Reference: Who Covers What

Use this table to find the right researcher resource for each specific testing goal.

| Testing Goal | Best Resource | Researcher | URL |
|---|---|---|---|
| Classify an injection attack type | Arcanum PI Taxonomy | jhaddix / Arcanum-Sec | https://github.com/Arcanum-Sec/arc_pi_taxonomy |
| Generate obfuscated/encoded payloads | Parseltongue P4RS3LT0NGV3 | jhaddix / elder-plinius | https://github.com/Arcanum-Sec/P4RS3LT0NGV3 |
| Jailbreak GPT-4 / o1 / o3 | L1B3RT4S OPENAI.mkd | elder-plinius | https://github.com/elder-plinius/L1B3RT4S/blob/main/OPENAI.mkd |
| Jailbreak Claude | L1B3RT4S ANTHROPIC.mkd | elder-plinius | https://github.com/elder-plinius/L1B3RT4S/blob/main/ANTHROPIC.mkd |
| Jailbreak Gemini | L1B3RT4S GOOGLE.mkd | elder-plinius | https://github.com/elder-plinius/L1B3RT4S/blob/main/GOOGLE.mkd |
| Jailbreak Llama / Meta models | L1B3RT4S META.mkd | elder-plinius | https://github.com/elder-plinius/L1B3RT4S/blob/main/META.mkd |
| Jailbreak DeepSeek (reasoning) | L1B3RT4S DEEPSEEK.mkd | elder-plinius | https://github.com/elder-plinius/L1B3RT4S/blob/main/DEEPSEEK.mkd |
| Extract / study real system prompts | CL4R1T4S | elder-plinius | https://github.com/elder-plinius/CL4R1T4S |
| Multi-modal injection via images | STEGOSAURUS-WRECKS | elder-plinius | https://github.com/elder-plinius/STEGOSAURUS-WRECKS |
| Understand injection in bug bounty context | PIPE | jthack | https://github.com/jthack/PIPE |
| Automated injection scanning | promptmap | utkusen | https://github.com/utkusen/promptmap |
| Indirect injection PoC demos | llm-security | greshake | https://github.com/greshake/llm-security |
| OWASP-aligned test case library | pentest-book LLM section | six2dez | https://github.com/six2dez/pentest-book/blob/master/others/llm-ai-ml-prompt-testing.md |
| In-the-wild jailbreak dataset | jailbreak_llms | verazuo | https://github.com/verazuo/jailbreak_llms |
| Benchmark jailbreak success rate | JailbreakBench | JailbreakBench org | https://github.com/JailbreakBench/jailbreakbench |
| System prompt collection (broader) | system-prompts-and-models-of-ai-tools | x1xhlol / jhaddix fork | https://github.com/jhaddix/system-prompts-and-models-of-ai-tools |
| AI pentest assessment questionnaire | ai-sec-resources | Arcanum-Sec | https://github.com/Arcanum-Sec/ai-sec-resources |
| Agentic security (2026 OWASP) | LLMSecurityGuide | requie | https://github.com/requie/LLMSecurityGuide |

---

### Quick Reference — Social / Follow

| Person | GitHub | Twitter/X | Focus |
|---|---|---|---|
| Jason Haddix | https://github.com/jhaddix | @jhaddix | AI pentesting methodology, prompt injection taxonomy, offensive security |
| Elder Plinius | https://github.com/elder-plinius | @elder_plinius | Jailbreaks, system prompt extraction, multi-modal injection, #LIBERTAS |
| Joseph Thacker | https://github.com/jthack | @rez0__ | Prompt injection engineering, bug bounty in AI context |
| Simon Willison | https://github.com/simonw | @simonw | Indirect injection research, LLM security writing |
| Johann Rehberger | https://github.com/wunderwuzzi23 | @wunderwuzzi23 | Indirect injection PoC, real-world exploits against Bing, ChatGPT plugins |

---

*All links verified February 2025. All resources listed are for authorized security testing in lab environments only.*
