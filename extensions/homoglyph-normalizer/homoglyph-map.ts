const BASE_HOMOGLYPH_ENTRIES: Array<[string, string]> = [
  // Cyrillic → Latin
  ["\u0430", "a"],
  ["\u0435", "e"],
  ["\u043E", "o"],
  ["\u0440", "p"],
  ["\u0441", "c"],
  ["\u0443", "y"],
  ["\u0445", "x"],
  ["\u0410", "A"],
  ["\u0412", "B"],
  ["\u0415", "E"],
  ["\u041A", "K"],
  ["\u041C", "M"],
  ["\u041D", "H"],
  ["\u041E", "O"],
  ["\u0420", "P"],
  ["\u0421", "C"],
  ["\u0422", "T"],
  ["\u0425", "X"],
  ["\u0456", "i"],
  ["\u0458", "j"],
  ["\u0455", "s"],
  ["\u0501", "d"],
  ["\u051B", "q"],
  ["\u051D", "w"],
  ["\u0406", "I"],

  // Greek → Latin
  ["\u0391", "A"],
  ["\u0392", "B"],
  ["\u0395", "E"],
  ["\u0396", "Z"],
  ["\u0397", "H"],
  ["\u0399", "I"],
  ["\u039A", "K"],
  ["\u039C", "M"],
  ["\u039D", "N"],
  ["\u039F", "O"],
  ["\u03A1", "P"],
  ["\u03A4", "T"],
  ["\u03A5", "Y"],
  ["\u03A7", "X"],
  ["\u03BF", "o"],

  // Other confusables
  ["\u0131", "i"],
  ["\u2113", "l"],
  ["\u2170", "i"],
  ["\u217C", "l"],
  ["\u2070", "0"],
];

export const HOMOGLYPH_MAP: Map<string, string> = new Map(BASE_HOMOGLYPH_ENTRIES);

for (let codePoint = 0xff21; codePoint <= 0xff3a; codePoint += 1) {
  HOMOGLYPH_MAP.set(String.fromCodePoint(codePoint), String.fromCodePoint(codePoint - 0xfee0));
}

for (let codePoint = 0xff41; codePoint <= 0xff5a; codePoint += 1) {
  HOMOGLYPH_MAP.set(String.fromCodePoint(codePoint), String.fromCodePoint(codePoint - 0xfee0));
}
