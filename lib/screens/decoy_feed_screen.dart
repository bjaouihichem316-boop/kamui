import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

/// Decoy News Feed UI displayed when Duress PIN is entered.
/// Looks like a standard harmless news reader app.
class DecoyFeedScreen extends StatelessWidget {
  const DecoyFeedScreen({super.key});

  static const _mockArticles = [
    {
      'title':   'Global Quantum Computing Breakthrough Announced',
      'source':  'Tech Spectrum',
      'time':    '10m ago',
      'snippet': 'Researchers demonstrate fault-tolerant 1000-qubit processor with high fidelity operational gates.',
    },
    {
      'title':   'Open Source AI Models Reach New Benchmarks',
      'source':  'Dev Digest',
      'time':    '42m ago',
      'snippet': 'New open architecture model outperforms legacy proprietary systems in coding and mathematical reasoning.',
    },
    {
      'title':   'Next-Gen Battery Technology Enters Mass Production',
      'source':  'Energy Wire',
      'time':    '2h ago',
      'snippet': 'Solid-state silicon anode cells achieve 500 Wh/kg energy density with 10-minute fast charging capabilities.',
    },
    {
      'title':   'Web Standards Committee Finalizes New Canvas API',
      'source':  'W3C Updates',
      'time':    '4h ago',
      'snippet': 'High-performance GPU compute shaders bringing native raytracing capabilities directly to web standards.',
    },
    {
      'title':   'Autonomous Transit Network Expands to 10 New Cities',
      'source':  'Urban Tech Daily',
      'time':    '6h ago',
      'snippet': 'Zero-emission electric vehicle fleets record over 100 million miles without safety incidents.',
    },
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0F0F12),
      appBar: AppBar(
        backgroundColor: const Color(0xFF16161C),
        elevation: 0,
        title: Text(
          'Tech Spectrum Reader',
          style: GoogleFonts.inter(
            fontSize: 16,
            fontWeight: FontWeight.w600,
            color: Colors.white,
          ),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_rounded, color: Colors.white70),
            onPressed: () {},
          ),
        ],
      ),
      body: ListView.builder(
        padding: const EdgeInsets.all(16),
        itemCount: _mockArticles.length,
        itemBuilder: (_, i) {
          final article = _mockArticles[i];
          return Card(
            color: const Color(0xFF1C1C24),
            margin: const EdgeInsets.only(bottom: 12),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(10),
            ),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        article['source']!,
                        style: GoogleFonts.inter(
                          fontSize: 11,
                          fontWeight: FontWeight.w600,
                          color: const Color(0xFF3B82F6),
                        ),
                      ),
                      Text(
                        article['time']!,
                        style: GoogleFonts.inter(
                          fontSize: 10,
                          color: Colors.white38,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Text(
                    article['title']!,
                    style: GoogleFonts.inter(
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                      color: Colors.white,
                      height: 1.3,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    article['snippet']!,
                    style: GoogleFonts.inter(
                      fontSize: 12,
                      color: Colors.white70,
                      height: 1.4,
                    ),
                  ),
                ],
              ),
            ),
          );
        },
      ),
    );
  }
}
