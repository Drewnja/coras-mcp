"""Text metrics for the fonts the Threat Modelling Tool draws labels with.

The widths below were measured with java.awt.FontMetrics for
Font("SansSerif", PLAIN, 12) -- the default font the editor stores in a .dgx --
so node sizes computed here match what the editor actually renders.
Widths for other point sizes are scaled linearly, which is accurate to about a
pixel for the sizes anyone uses in a diagram.
"""

# "codepoint:advance," pairs, measured on the JVM (ASCII + Cyrillic + punctuation).
_RAW_WIDTHS_12 = (
    "32:4,33:4,34:4,35:8,36:8,37:8,38:8,39:3,40:4,41:4,42:6,43:10,44:4,45:7,46:4,47:6,48:8,49:8,50:8,51:8,52:8,53:8,54:8,55:8,56:8,57:8,58:4,59:4,60:10,61:10,62:10,63:5,64:10,65:8,66:7,67:8,68:9,69:7,70:6,71:9,72:9,73:3,74:4,75:8,76:6,77:10,78:9,79:9,80:7,81:9,82:8,83:6,84:8,85:8,86:8,87:10,88:8,89:7,90:7,91:4,92:6,93:4,94:8,95:6,96:7,97:7,98:8,99:6,100:8,101:7,102:4,103:7,104:7,105:3,106:4,107:7,108:3,109:11,110:7,111:7,112:8,113:8,114:5,115:6,116:4,117:7,118:6,119:9,120:7,121:6,122:7,123:4,124:4,125:4,126:8,1024:7,1025:7,1026:9,1027:6,1028:8,1029:6,1030:3,1031:3,1032:4,1033:12,1034:12,1035:9,1036:8,1037:9,1038:8,1039:9,1040:8,1041:7,1042:7,1043:6,1044:9,1045:7,1046:10,1047:6,1048:9,1049:9,1050:8,1051:8,1052:10,1053:9,1054:9,1055:9,1056:7,1057:8,1058:8,1059:8,1060:8,1061:8,1062:9,1063:8,1064:11,1065:12,1066:8,1067:10,1068:7,1069:8,1070:12,1071:7,1072:7,1073:7,1074:6,1075:6,1076:8,1077:7,1078:9,1079:6,1080:8,1081:8,1082:7,1083:7,1084:9,1085:8,1086:7,1087:8,1088:8,1089:6,1090:6,1091:6,1092:9,1093:7,1094:8,1095:6,1096:10,1097:10,1098:7,1099:9,1100:6,1101:6,1102:10,1103:6,1104:7,1105:7,1106:8,1107:6,1108:6,1109:6,1110:3,1111:3,1112:4,1113:9,1114:10,1115:8,1116:7,1117:8,1118:6,1119:8,8211:6,8212:12,8216:4,8217:4,8220:5,8221:5,8230:12,171:6,187:6,160:4,1105:7,1025:7,"
)

#: Line height of SansSerif 12 (ascent 12 + descent 3).
LINE_HEIGHT_12 = 15
BASE_SIZE = 12
#: Fallback advance for characters that were not measured.
_DEFAULT_WIDTH_12 = 8

_WIDTHS_12 = {}
for _pair in _RAW_WIDTHS_12.split(","):
    if not _pair:
        continue
    _cp, _, _w = _pair.partition(":")
    _WIDTHS_12[int(_cp)] = int(_w)
del _pair, _cp, _w


def char_width(ch, size=BASE_SIZE):
    """Advance width of a single character, in pixels."""
    w = _WIDTHS_12.get(ord(ch), _DEFAULT_WIDTH_12)
    if size == BASE_SIZE:
        return w
    return w * size / float(BASE_SIZE)


def text_width(text, size=BASE_SIZE, bold=False):
    """Width of a single line of text, in pixels."""
    total = 0.0
    for ch in text:
        total += _WIDTHS_12.get(ord(ch), _DEFAULT_WIDTH_12)
    if bold:
        total *= 1.08
    if size != BASE_SIZE:
        total = total * size / float(BASE_SIZE)
    return total


def line_height(size=BASE_SIZE):
    """Height of one rendered line of text, in pixels."""
    if size == BASE_SIZE:
        return LINE_HEIGHT_12
    return max(1, int(round(LINE_HEIGHT_12 * size / float(BASE_SIZE))))


def wrap(text, max_width, size=BASE_SIZE, bold=False):
    """Greedy word wrap, the way a Swing JLabel lays out <html> text.

    Returns the list of lines. Explicit newlines in *text* are honoured.
    Words wider than *max_width* are broken character by character.
    """
    lines = []
    for paragraph in str(text).split("\n"):
        words = paragraph.split()
        if not words:
            lines.append("")
            continue
        current = ""
        for word in words:
            candidate = word if not current else current + " " + word
            if text_width(candidate, size, bold) <= max_width or not current:
                if text_width(candidate, size, bold) <= max_width:
                    current = candidate
                    continue
                # Single word too wide for the line: break it up.
                if current:
                    lines.append(current)
                    current = ""
                piece = ""
                for ch in word:
                    if piece and text_width(piece + ch, size, bold) > max_width:
                        lines.append(piece)
                        piece = ch
                    else:
                        piece += ch
                current = piece
            else:
                lines.append(current)
                current = word
        if current:
            lines.append(current)
    return lines or [""]


def wrapped_size(text, max_width, size=BASE_SIZE, bold=False):
    """(width, height, lines) of *text* wrapped at *max_width*."""
    lines = wrap(text, max_width, size, bold)
    width = max((text_width(line, size, bold) for line in lines), default=0.0)
    return width, len(lines) * line_height(size), lines


def best_fit(text, min_width, max_width, size=BASE_SIZE, aspect=2.4, bold=False):
    """Pick a text-box width that keeps a label close to *aspect* (w:h).

    Tries candidate widths from narrow to wide and returns the first one whose
    wrapped block is no taller than the aspect ratio allows, so short labels
    stay on one line and long ones wrap into a compact block instead of a
    very long strip.
    """
    single = text_width(text, size, bold)
    if single <= min_width:
        return min_width, line_height(size), [str(text)]
    step = max(8, int((max_width - min_width) / 12) or 8)
    width = min_width
    best = None
    while width <= max_width:
        w, h, lines = wrapped_size(text, width, size, bold)
        if best is None:
            best = (w, h, lines)
        if w / float(max(h, 1)) >= aspect:
            return w, h, lines
        best = (w, h, lines)
        width += step
    w, h, lines = wrapped_size(text, max_width, size, bold)
    return w, h, lines
