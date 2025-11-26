/* hex_data_source_view.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// Some code based on QHexView by Evan Teran
// https://github.com/eteran/qhexview/

#include "hex_data_source_view.h"

#include <wsutil/str_util.h>

#include <wsutil/application_flavor.h>
#include <wsutil/utf8_entities.h>

#include <ui/qt/utils/color_utils.h>
#include "main_application.h"
#include "ui/recent.h"

#include <QActionGroup>
#include <QMouseEvent>
#include <QPainter>
#include <QScreen>
#include <QScrollBar>
#include <QStyle>
#include <QStyleOption>
#include <QTextLayout>
#include <QWindow>

// To do:
// - Add recent settings and context menu items to show/hide the offset.
// - Add a UTF-8 and possibly UTF-xx option to the ASCII display.
// - Move more common metrics to DataPrinter.

// Alternative implementations:
// - Pre-draw all of our characters and paint our display using pixmap
//   copying? That would make this behave like a terminal screen, which
//   is what we ultimately want.
// - Use QGraphicsView + QGraphicsScene + QGraphicsTextItem instead?

Q_DECLARE_METATYPE(bytes_view_type)
Q_DECLARE_METATYPE(bytes_encoding_type)
Q_DECLARE_METATYPE(DataPrinter::DumpType)

HexDataSourceView::HexDataSourceView(const QByteArray &data, packet_char_enc encoding, QWidget *parent) :
    BaseDataSourceView(data, parent),
    layout_(new QTextLayout()),
    layout_dirty_(false),
    encoding_(encoding),
    hovered_byte_offset_(-1),
    marked_byte_offset_(-1),
    selected_byte_offset_(-1),
    proto_start_(0),
    proto_len_(0),
    field_start_(0),
    field_len_(0),
    field_a_start_(0),
    field_a_len_(0),
    show_offset_(true),
    show_hex_(true),
    show_ascii_(true),
    row_width_(recent.gui_bytes_view == BYTES_BITS ? 8 : (recent.gui_bytes_view == BYTES_UTF8_TEXT ? 80 : 16)),
    em_width_(0),
    line_height_(0),
    allow_hover_selection_(false)
{
    layout_->setCacheEnabled(true);

    offset_normal_fg_ = ColorUtils::alphaBlend(palette().windowText(), palette().window(), 0.35);
    offset_field_fg_ = ColorUtils::alphaBlend(palette().windowText(), palette().window(), 0.65);
    ctx_menu_.setToolTipsVisible(true);

    window()->winId(); // Required for screenChanged? https://phabricator.kde.org/D20171
    connect(window()->windowHandle(), &QWindow::screenChanged, viewport(), [=](const QScreen *) { viewport()->update(); });

    setMouseTracking(true);

#ifdef Q_OS_MAC
    setAttribute(Qt::WA_MacShowFocusRect, true);
#endif
}

HexDataSourceView::~HexDataSourceView()
{
    ctx_menu_.clear();
    delete(layout_);
}

void HexDataSourceView::createContextMenu()
{

    action_allow_hover_selection_ = ctx_menu_.addAction(tr("Allow hover highlighting"));
    action_allow_hover_selection_->setCheckable(true);
    action_allow_hover_selection_->setChecked(true);
    connect(action_allow_hover_selection_, &QAction::toggled, this, &HexDataSourceView::toggleHoverAllowed);
    ctx_menu_.addSeparator();

    QActionGroup * copy_actions = DataPrinter::copyActions(this);
    ctx_menu_.addActions(copy_actions->actions());
    ctx_menu_.addSeparator();

    QActionGroup * format_actions = new QActionGroup(this);
    action_bytes_hex_ = format_actions->addAction(tr("Show bytes as hexadecimal"));
    action_bytes_hex_->setData(QVariant::fromValue(BYTES_HEX));
    action_bytes_hex_->setCheckable(true);

    action_bytes_dec_ = format_actions->addAction(tr("…as decimal"));
    action_bytes_dec_->setData(QVariant::fromValue(BYTES_DEC));
    action_bytes_dec_->setCheckable(true);

    action_bytes_oct_ = format_actions->addAction(tr("…as octal"));
    action_bytes_oct_->setData(QVariant::fromValue(BYTES_OCT));
    action_bytes_oct_->setCheckable(true);

    action_bytes_bits_ = format_actions->addAction(tr("…as bits"));
    action_bytes_bits_->setData(QVariant::fromValue(BYTES_BITS));
    action_bytes_bits_->setCheckable(true);

    action_bytes_utf8_text_ = format_actions->addAction(tr("…as UTF-8 text only"));
    action_bytes_utf8_text_->setData(QVariant::fromValue(BYTES_UTF8_TEXT));
    action_bytes_utf8_text_->setCheckable(true);

    ctx_menu_.addActions(format_actions->actions());
    connect(format_actions, &QActionGroup::triggered, this, &HexDataSourceView::setHexDisplayFormat);

    ctx_menu_.addSeparator();

    QActionGroup * encoding_actions = new QActionGroup(this);
    if (application_flavor_is_wireshark()) {
        action_bytes_enc_from_packet_ = encoding_actions->addAction(tr("Show text as frame encoding"));
    } else {
        action_bytes_enc_from_packet_ = encoding_actions->addAction(tr("Show text based on event"));
    }
    action_bytes_enc_from_packet_->setData(QVariant::fromValue(BYTES_ENC_FROM_PACKET));
    action_bytes_enc_from_packet_->setCheckable(true);

    action_bytes_enc_ascii_ = encoding_actions->addAction(tr("…as ASCII"));
    action_bytes_enc_ascii_->setData(QVariant::fromValue(BYTES_ENC_ASCII));
    action_bytes_enc_ascii_->setCheckable(true);

    action_bytes_enc_ebcdic_ = encoding_actions->addAction(tr("…as EBCDIC"));
    action_bytes_enc_ebcdic_->setData(QVariant::fromValue(BYTES_ENC_EBCDIC));
    action_bytes_enc_ebcdic_->setCheckable(true);

    updateContextMenu();

    ctx_menu_.addActions(encoding_actions->actions());
    connect(encoding_actions, &QActionGroup::triggered, this, &HexDataSourceView::setCharacterEncoding);
}

void HexDataSourceView::toggleHoverAllowed(bool checked)
{
    allow_hover_selection_ = ! checked;
    recent.gui_allow_hover_selection = checked;
}

void HexDataSourceView::updateContextMenu()
{
    if (ctx_menu_.isEmpty()) {
        return;
    }

    action_allow_hover_selection_->setChecked(recent.gui_allow_hover_selection);

    switch (recent.gui_bytes_view) {
    case BYTES_HEX:
        action_bytes_hex_->setChecked(true);
        break;
    case BYTES_BITS:
        action_bytes_bits_->setChecked(true);
        break;
    case BYTES_DEC:
        action_bytes_dec_->setChecked(true);
        break;
    case BYTES_OCT:
        action_bytes_oct_->setChecked(true);
        break;
    case BYTES_UTF8_TEXT:
        action_bytes_utf8_text_->setChecked(true);
        break;
    }

    switch (recent.gui_bytes_encoding) {
    case BYTES_ENC_FROM_PACKET:
        action_bytes_enc_from_packet_->setChecked(true);
        break;
    case BYTES_ENC_ASCII:
        action_bytes_enc_ascii_->setChecked(true);
        break;
    case BYTES_ENC_EBCDIC:
        action_bytes_enc_ebcdic_->setChecked(true);
        break;
    }
}

void HexDataSourceView::markProtocol(int start, int length)
{
    proto_start_ = start;
    proto_len_ = length;
    viewport()->update();
}

void HexDataSourceView::markField(int start, int length, bool scroll_to)
{
    field_start_ = start;
    field_len_ = length;
    // This might be called as a result of (de)selecting a proto tree
    // item, so take us out of marked mode.
    marked_byte_offset_ = -1;
    if (scroll_to) {
        scrollToByte(start);
    }
    viewport()->update();
}

void HexDataSourceView::saveSelected(int start)
{
    selected_byte_offset_ = start;
}

void HexDataSourceView::markAppendix(int start, int length)
{
    field_a_start_ = start;
    field_a_len_ = length;
    viewport()->update();
}

void HexDataSourceView::unmarkField()
{
    proto_start_ = 0;
    proto_len_ = 0;
    field_start_ = 0;
    field_len_ = 0;
    marked_byte_offset_ = -1;
    field_a_start_ = 0;
    field_a_len_ = 0;
    viewport()->update();
}

void HexDataSourceView::setMonospaceFont(const QFont &mono_font)
{
    QFont int_font(mono_font);

    setFont(int_font);
    viewport()->setFont(int_font);
    layout_->setFont(int_font);

    if (isVisible()) {
        updateLayoutMetrics();
        updateScrollbars();
        viewport()->update();
    } else {
        layout_dirty_ = true;
    }
}

void HexDataSourceView::updateByteViewSettings()
{
    if (recent.gui_bytes_view == BYTES_BITS) {
        row_width_ = 8;
        show_offset_ = true;
        show_hex_ = true;
        show_ascii_ = true;
    } else if (recent.gui_bytes_view == BYTES_UTF8_TEXT) {
        // For UTF-8 text mode, row_width_ represents approximate bytes per line
        // Actual character count will be calculated dynamically based on viewport width
        row_width_ = 100;  // Initial estimate, will be adjusted during rendering
        show_offset_ = false;
        show_hex_ = false;
        show_ascii_ = false;  // We render UTF-8 text directly, not ASCII
    } else {
        row_width_ = 16;
        show_offset_ = true;
        show_hex_ = true;
        show_ascii_ = true;
    }

    updateContextMenu();
    updateScrollbars();
    viewport()->update();
}

void HexDataSourceView::paintEvent(QPaintEvent *)
{
    updateLayoutMetrics();

    QPainter painter(viewport());
    painter.translate(-horizontalScrollBar()->value() * em_width_, 0);

    // Pixel offset of this row
    int row_y = 0;

    // Starting byte offset
    int offset;
    if (recent.gui_bytes_view == BYTES_UTF8_TEXT) {
        // For UTF-8 text mode, estimate bytes per line
        int estimated_bytes_per_line = 50;
        offset = verticalScrollBar()->value() * estimated_bytes_per_line;
    } else {
        offset = verticalScrollBar()->value() * row_width_;
    }

    // Clear the area
    painter.fillRect(viewport()->rect(), palette().base());

    // Offset background. We want the entire height to be filled.
    if (show_offset_) {
        QRect offset_rect = QRect(viewport()->rect());
        offset_rect.setWidth(offsetPixels());
        painter.fillRect(offset_rect, palette().window());
    }

    if (data_.isEmpty()) {
        return;
    }

    // Data rows
    int widget_height = height();
    painter.save();

    if (recent.gui_bytes_view != BYTES_UTF8_TEXT) {
        x_pos_to_column_.clear();
    }
    
    while ((int) (row_y + line_height_) < widget_height && offset < (int) data_.size()) {
        if (recent.gui_bytes_view == BYTES_UTF8_TEXT) {
            // For UTF-8 text mode, we need to calculate bytes per line dynamically
            // Estimate based on viewport width and average character width
            int estimated_chars_per_line = viewport()->width() / em_width_;
            int estimated_bytes_per_line = estimated_chars_per_line * 2;  // Conservative: assume 2 bytes per char on average
            drawLine(&painter, offset, row_y);
            offset += estimated_bytes_per_line;
        } else {
            drawLine(&painter, offset, row_y);
            offset += row_width_;
        }
        row_y += line_height_;
    }

    painter.restore();

    // We can't do this in drawLine since the next line might draw over our rect.
    // This looks best when our highlight and background have similar lightnesses.
    // We might want to set a composition mode when that's not the case.
    if (!hover_outlines_.isEmpty()) {
        qreal pen_width = 1.0;
        qreal hover_alpha = 0.6;
        QPen ho_pen;
        QColor ho_color = palette().text().color();
        if (marked_byte_offset_ < 0) {
            hover_alpha = 0.3;
            if (devicePixelRatio() > 1) {
                pen_width = 0.5;
            }
        }
        ho_pen.setWidthF(pen_width);
        ho_color.setAlphaF(hover_alpha);
        ho_pen.setColor(ho_color);

        painter.save();
        painter.setPen(ho_pen);
        painter.setBrush(Qt::NoBrush);
        foreach (QRect ho_rect, hover_outlines_) {
            // These look good on retina and non-retina displays on macOS.
            // We might want to use fontMetrics numbers instead.
            ho_rect.adjust(-1, 0, -1, -1);
            painter.drawRect(ho_rect);
        }
        painter.restore();
    }
    hover_outlines_.clear();

    QStyleOptionFocusRect option;
    option.initFrom(this);
    style()->drawPrimitive(QStyle::PE_FrameFocusRect, &option, &painter, this);
}

void HexDataSourceView::resizeEvent(QResizeEvent *)
{
    updateScrollbars();
}

void HexDataSourceView::showEvent(QShowEvent *)
{
    if (layout_dirty_) {
        updateLayoutMetrics();
        updateScrollbars();
        viewport()->update();
        layout_dirty_ = false;
    }
}

void HexDataSourceView::mousePressEvent (QMouseEvent *event) {
    if (data_.isEmpty() || !event || event->button() != Qt::LeftButton) {
        return;
    }

    // byteSelected does the following:
    // - Triggers selectedFieldChanged in ProtoTree, which clears the
    //   selection and selects the corresponding (or no) item.
    // - The new tree selection triggers markField, which clobbers
    //   marked_byte_offset_.

    const bool hover_mode = marked_byte_offset_ < 0;
    const int byte_offset = byteOffsetAtPixel(event->pos());
    setUpdatesEnabled(false);
    emit byteSelected(byte_offset);
    selected_byte_offset_ = byte_offset;
    if (hover_mode && byte_offset >= 0) {
        // Switch to marked mode.
        hovered_byte_offset_ = -1;
        marked_byte_offset_ = byte_offset;
        viewport()->update();
    } else {
        // Back to hover mode.
        mouseMoveEvent(event);
    }
    setUpdatesEnabled(true);
}

void HexDataSourceView::mouseMoveEvent(QMouseEvent *event)
{
    if (marked_byte_offset_ >= 0 || allow_hover_selection_ ||
        (!allow_hover_selection_ && event->modifiers() & Qt::ControlModifier)) {
        return;
    }

    hovered_byte_offset_ = byteOffsetAtPixel(event->pos());
    emit byteHovered(hovered_byte_offset_);
    viewport()->update();
}

void HexDataSourceView::leaveEvent(QEvent *event)
{
    hovered_byte_offset_ = -1;
    emit byteHovered(hovered_byte_offset_);

    emit byteSelected(selected_byte_offset_);

    viewport()->update();
    QAbstractScrollArea::leaveEvent(event);
}

void HexDataSourceView::contextMenuEvent(QContextMenuEvent *event)
{
    if (ctx_menu_.isEmpty()) {
        createContextMenu();
    }
    ctx_menu_.popup(event->globalPos());
}

// Private

const int HexDataSourceView::separator_interval_ = DataPrinter::separatorInterval();

void HexDataSourceView::updateLayoutMetrics()
{
    em_width_  = stringWidth("M");
    // We might want to match ProtoTree::rowHeight.
    line_height_ = viewport()->fontMetrics().lineSpacing();
}

int HexDataSourceView::stringWidth(const QString &line)
{
    return viewport()->fontMetrics().horizontalAdvance(line);
}

// Draw a line of byte view text for a given offset.
// Text highlighting is handled using QTextLayout::FormatRange.
void HexDataSourceView::drawLine(QPainter *painter, const int offset, const int row_y)
{
    if (data_.isEmpty()) {
        return;
    }

    // UTF-8 text-only mode
    if (recent.gui_bytes_view == BYTES_UTF8_TEXT) {
        int tvb_len = static_cast<int>(data_.size());
        
        // Calculate how many bytes we can display in one line based on viewport width
        // We'll process bytes incrementally and stop when we exceed the viewport width
        int viewport_width = viewport()->width();
        int max_bytes_to_process = qMin(offset + 1000, tvb_len);  // Process up to 1000 bytes at a time
        QByteArray line_data = data_.mid(offset, max_bytes_to_process - offset);
        
        // Convert to UTF-8 string, handling invalid sequences gracefully
        QString line = QString::fromUtf8(line_data.constData(), line_data.size());
        
        // Process characters and build display string, replacing non-printable with middle dot
        QString result;
        QVector<int> byte_to_char_map;  // Maps byte positions to character indices
        int byte_pos = offset;
        const char *data_ptr = line_data.constData();
        int data_len = line_data.size();
        
        for (int char_index = 0; char_index < line.length() && byte_pos < offset + data_len; char_index++) {
            QChar ch = line.at(char_index);
            
            // Determine UTF-8 byte length for this character
            int utf8_bytes = 1;
            if (byte_pos < offset + data_len) {
                unsigned char first_byte = static_cast<unsigned char>(data_ptr[byte_pos - offset]);
                if ((first_byte & 0x80) == 0) {
                    utf8_bytes = 1;  // ASCII
                } else if ((first_byte & 0xE0) == 0xC0) {
                    utf8_bytes = 2;
                } else if ((first_byte & 0xF0) == 0xE0) {
                    utf8_bytes = 3;
                } else if ((first_byte & 0xF8) == 0xF0) {
                    utf8_bytes = 4;
                }
            }
            
            // Check if character is printable
            if (ch.isPrint() || ch == QChar::Space || ch == QChar::Tab || 
                ch == QChar::LineFeed || ch == QChar::CarriageReturn) {
                result += ch;
            } else if (ch.unicode() == 0xFFFD) {
                // Unicode replacement character (invalid UTF-8 sequence)
                result += QChar(0x00B7);  // Middle dot
            } else {
                result += QChar(0x00B7);  // Middle dot for other non-printable
            }
            
            // Map bytes to character position
            for (int b = 0; b < utf8_bytes && byte_pos < offset + data_len; b++) {
                byte_to_char_map.append(char_index);
                byte_pos++;
            }
        }
        
        // Truncate result to fit viewport width
        int text_width = stringWidth(result);
        if (text_width > viewport_width && result.length() > 0) {
            // Find the character position that fits within viewport
            int fit_chars = 0;
            int current_width = 0;
            for (int i = 0; i < result.length(); i++) {
                int char_width = stringWidth(QString(result.at(i)));
                if (current_width + char_width > viewport_width) {
                    break;
                }
                current_width += char_width;
                fit_chars++;
            }
            if (fit_chars < result.length()) {
                result = result.left(fit_chars);
            }
        }
        
        // Build x_pos mapping for byte selection
        bool build_x_pos = x_pos_to_column_.empty();
        if (build_x_pos) {
            x_pos_to_column_.clear();
            int x_pos = 0;
            for (int i = 0; i < result.length(); i++) {
                QChar ch = result.at(i);
                int char_width = stringWidth(QString(ch));
                
                // Find the byte offset for this character
                int byte_offset = -1;
                if (i < byte_to_char_map.size()) {
                    // Find first byte position that maps to this character
                    for (int b = 0; b < byte_to_char_map.size(); b++) {
                        if (byte_to_char_map[b] == i) {
                            byte_offset = b;
                            break;
                        }
                    }
                }
                if (byte_offset < 0) {
                    byte_offset = i;  // Fallback
                }
                
                // Map each pixel position to the byte offset
                for (int j = 0; j < char_width; j++) {
                    x_pos_to_column_.append(byte_offset);
                }
                x_pos += char_width;
            }
        }
        
        // Calculate actual bytes displayed
        int max_tvb_pos = offset + (byte_to_char_map.size() > 0 ? byte_to_char_map.size() : result.length());
        max_tvb_pos = qMin(max_tvb_pos, tvb_len);
        
        QList<QTextLayout::FormatRange> fmt_list;
        
        // Add highlighting for selected fields
        // For text mode, we need to map byte ranges to character ranges
        if (field_start_ >= offset && field_start_ < max_tvb_pos && field_len_ > 0) {
            int field_byte_start = field_start_ - offset;
            int field_byte_end = qMin(field_byte_start + field_len_, byte_to_char_map.size());
            
            if (field_byte_start >= 0 && field_byte_start < byte_to_char_map.size()) {
                int field_char_start = byte_to_char_map[field_byte_start];
                int field_char_end = (field_byte_end < byte_to_char_map.size()) 
                    ? byte_to_char_map[field_byte_end - 1] + 1 
                    : result.length();
                field_char_end = qMin(field_char_end, result.length());
                
                if (field_char_start < result.length() && field_char_end > field_char_start) {
                    QTextLayout::FormatRange fmt_range;
                    fmt_range.start = field_char_start;
                    fmt_range.length = field_char_end - field_char_start;
                    fmt_range.format.setBackground(palette().highlight());
                    fmt_range.format.setForeground(palette().highlightedText());
                    fmt_list.append(fmt_range);
                }
            }
        }
        
        if (proto_start_ >= offset && proto_start_ < max_tvb_pos && proto_len_ > 0) {
            int proto_byte_start = proto_start_ - offset;
            int proto_byte_end = qMin(proto_byte_start + proto_len_, byte_to_char_map.size());
            
            if (proto_byte_start >= 0 && proto_byte_start < byte_to_char_map.size()) {
                int proto_char_start = byte_to_char_map[proto_byte_start];
                int proto_char_end = (proto_byte_end < byte_to_char_map.size()) 
                    ? byte_to_char_map[proto_byte_end - 1] + 1 
                    : result.length();
                proto_char_end = qMin(proto_char_end, result.length());
                
                if (proto_char_start < result.length() && proto_char_end > proto_char_start) {
                    QTextLayout::FormatRange fmt_range;
                    fmt_range.start = proto_char_start;
                    fmt_range.length = proto_char_end - proto_char_start;
                    fmt_range.format.setBackground(palette().window());
                    fmt_range.format.setForeground(palette().windowText());
                    fmt_list.append(fmt_range);
                }
            }
        }
        
        if (field_a_start_ >= offset && field_a_start_ < max_tvb_pos && field_a_len_ > 0) {
            int field_a_byte_start = field_a_start_ - offset;
            int field_a_byte_end = qMin(field_a_byte_start + field_a_len_, byte_to_char_map.size());
            
            if (field_a_byte_start >= 0 && field_a_byte_start < byte_to_char_map.size()) {
                int field_a_char_start = byte_to_char_map[field_a_byte_start];
                int field_a_char_end = (field_a_byte_end < byte_to_char_map.size()) 
                    ? byte_to_char_map[field_a_byte_end - 1] + 1 
                    : result.length();
                field_a_char_end = qMin(field_a_char_end, result.length());
                
                if (field_a_char_start < result.length() && field_a_char_end > field_a_char_start) {
                    QTextLayout::FormatRange fmt_range;
                    fmt_range.start = field_a_char_start;
                    fmt_range.length = field_a_char_end - field_a_char_start;
                    fmt_range.format.setBackground(palette().highlight());
                    fmt_range.format.setForeground(palette().highlightedText());
                    fmt_list.append(fmt_range);
                }
            }
        }
        
        layout_->clearLayout();
        layout_->clearFormats();
        layout_->setText(result);
        layout_->setFormats(fmt_list.toVector());
        layout_->beginLayout();
        QTextLine tl = layout_->createLine();
        tl.setLineWidth(totalPixels());
        tl.setLeadingIncluded(true);
        layout_->endLayout();
        layout_->draw(painter, QPointF(0.0, row_y));
        return;
    }

    // Build our pixel to byte offset vector the first time through.
    bool build_x_pos = x_pos_to_column_.empty() ? true : false;
    int tvb_len = static_cast<int>(data_.size());
    int max_tvb_pos = qMin(offset + row_width_, tvb_len) - 1;
    QList<QTextLayout::FormatRange> fmt_list;

    static const char hexchars[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    QString line;
    HighlightMode offset_mode = ModeOffsetNormal;

    // Offset.
    if (show_offset_) {
        line = QStringLiteral(" %1 ").arg(offset, offsetChars(false), 16, QChar('0'));
        if (build_x_pos) {
            x_pos_to_column_.fill(-1, stringWidth(line));
        }
    }

    // Hex
    if (show_hex_) {
        int ascii_start = static_cast<int>(line.length()) + DataPrinter::hexChars() + 3;
        // Extra hover space before and after each byte.
        int slop = em_width_ / 2;
        unsigned char c;

        if (build_x_pos) {
            x_pos_to_column_ += QVector<int>().fill(-1, slop);
        }

        for (int tvb_pos = offset; tvb_pos <= max_tvb_pos; tvb_pos++) {
            line += ' ';
            /* insert a space every separator_interval_ bytes */
            if ((tvb_pos != offset) && ((tvb_pos % separator_interval_) == 0)) {
                line += ' ';
                x_pos_to_column_ += QVector<int>().fill(tvb_pos - offset - 1, em_width_);
            }

            switch (recent.gui_bytes_view) {
            case BYTES_HEX:
                line += hexchars[(data_[tvb_pos] & 0xf0) >> 4];
                line += hexchars[data_[tvb_pos] & 0x0f];
                break;
            case BYTES_BITS:
                /* XXX, bitmask */
                for (int j = 7; j >= 0; j--) {
                    line += (data_[tvb_pos] & (1 << j)) ? '1' : '0';
                }
                break;
            case BYTES_DEC:
                c = data_[tvb_pos];
                line += c < 100 ? ' ' : hexchars[c / 100];
                line += c < 10 ? ' ' : hexchars[(c / 10) % 10];
                line += hexchars[c % 10];
                break;
            case BYTES_OCT:
                line += hexchars[(data_[tvb_pos] & 0xc0) >> 6];
                line += hexchars[(data_[tvb_pos] & 0x38) >> 3];
                line += hexchars[data_[tvb_pos] & 0x07];
                break;
            case BYTES_UTF8_TEXT:
                // This case should not be reached here as it's handled earlier
                ws_assert_not_reached();
                break;
            }
            if (build_x_pos) {
                x_pos_to_column_ += QVector<int>().fill(tvb_pos - offset, stringWidth(line) - x_pos_to_column_.size() + slop);
            }
            if (tvb_pos == hovered_byte_offset_ || tvb_pos == marked_byte_offset_) {
                int ho_len;
                switch (recent.gui_bytes_view) {
                case BYTES_HEX:
                    ho_len = 2;
                    break;
                case BYTES_BITS:
                    ho_len = 8;
                    break;
                case BYTES_DEC:
                case BYTES_OCT:
                    ho_len = 3;
                    break;
                case BYTES_UTF8_TEXT:
                    // This case should not be reached here as it's handled earlier
                    ho_len = 1;
                    break;
                default:
                    ws_assert_not_reached();
                }
                QRect ho_rect = painter->boundingRect(QRect(), Qt::AlignHCenter|Qt::AlignVCenter, line.right(ho_len));
                ho_rect.moveRight(stringWidth(line));
                ho_rect.moveTop(row_y);
                hover_outlines_.append(ho_rect);
            }
        }
        line += QString(ascii_start - line.length(), ' ');
        if (build_x_pos) {
            x_pos_to_column_ += QVector<int>().fill(-1, stringWidth(line) - x_pos_to_column_.size());
        }

        addHexFormatRange(fmt_list, proto_start_, proto_len_, offset, max_tvb_pos, ModeProtocol);
        if (addHexFormatRange(fmt_list, field_start_, field_len_, offset, max_tvb_pos, ModeField)) {
            offset_mode = ModeOffsetField;
        }
        addHexFormatRange(fmt_list, field_a_start_, field_a_len_, offset, max_tvb_pos, ModeField);
    }

    // ASCII
    if (show_ascii_) {
        bool in_non_printable = false;
        int np_start = 0;
        int np_len = 0;
        char c;
        int bytes_enc;

        for (int tvb_pos = offset; tvb_pos <= max_tvb_pos; tvb_pos++) {
            /* insert a space every separator_interval_ bytes */
            if ((tvb_pos != offset) && ((tvb_pos % separator_interval_) == 0)) {
                line += ' ';
                if (build_x_pos) {
                    x_pos_to_column_ += QVector<int>().fill(tvb_pos - offset - 1, em_width_ / 2);
                }
            }

            if (recent.gui_bytes_encoding == BYTES_ENC_FROM_PACKET) {
                switch (encoding_) {
                case PACKET_CHAR_ENC_CHAR_ASCII:
                    bytes_enc = BYTES_ENC_ASCII;
                    break;
                case PACKET_CHAR_ENC_CHAR_EBCDIC:
                    bytes_enc = BYTES_ENC_EBCDIC;
                    break;
                default:
                    ws_assert_not_reached();
                }
            } else {
                bytes_enc = recent.gui_bytes_encoding;
            }

            switch (bytes_enc) {
            case BYTES_ENC_EBCDIC:
                c = EBCDIC_to_ASCII1(data_[tvb_pos]);
                break;
            case BYTES_ENC_ASCII:
            default:
                c = data_[tvb_pos];
                break;
            }

            if (g_ascii_isprint(c)) {
                line += c;
                if (in_non_printable) {
                    in_non_printable = false;
                    addAsciiFormatRange(fmt_list, np_start, np_len, offset, max_tvb_pos, ModeNonPrintable);
                }
            } else {
                line += UTF8_MIDDLE_DOT;
                if (!in_non_printable) {
                    in_non_printable = true;
                    np_start = tvb_pos;
                    np_len = 1;
                } else {
                    np_len++;
                }
            }
            if (build_x_pos) {
                x_pos_to_column_ += QVector<int>().fill(tvb_pos - offset, stringWidth(line) - x_pos_to_column_.size());
            }
            if (tvb_pos == hovered_byte_offset_ || tvb_pos == marked_byte_offset_) {
                QRect ho_rect = painter->boundingRect(QRect(), 0, line.right(1));
                ho_rect.moveRight(stringWidth(line));
                ho_rect.moveTop(row_y);
                hover_outlines_.append(ho_rect);
            }
        }
        if (in_non_printable) {
            addAsciiFormatRange(fmt_list, np_start, np_len, offset, max_tvb_pos, ModeNonPrintable);
        }
        addAsciiFormatRange(fmt_list, proto_start_, proto_len_, offset, max_tvb_pos, ModeProtocol);
        if (addAsciiFormatRange(fmt_list, field_start_, field_len_, offset, max_tvb_pos, ModeField)) {
            offset_mode = ModeOffsetField;
        }
        addAsciiFormatRange(fmt_list, field_a_start_, field_a_len_, offset, max_tvb_pos, ModeField);
    }

    // XXX Fields won't be highlighted if neither hex nor ascii are enabled.
    addFormatRange(fmt_list, 0, offsetChars(), offset_mode);

    layout_->clearLayout();
    layout_->clearFormats();
    layout_->setText(line);
    layout_->setFormats(fmt_list.toVector());
    layout_->beginLayout();
    QTextLine tl = layout_->createLine();
    tl.setLineWidth(totalPixels());
    tl.setLeadingIncluded(true);
    layout_->endLayout();
    layout_->draw(painter, QPointF(0.0, row_y));
}

bool HexDataSourceView::addFormatRange(QList<QTextLayout::FormatRange> &fmt_list, int start, int length, HighlightMode mode)
{
    if (length < 1)
        return false;

    QTextLayout::FormatRange format_range;
    format_range.start = start;
    format_range.length = length;
    switch (mode) {
    case ModeNormal:
        return false;
    case ModeField:
        format_range.format.setBackground(palette().highlight());
        format_range.format.setForeground(palette().highlightedText());
        break;
    case ModeProtocol:
        format_range.format.setBackground(palette().window());
        format_range.format.setForeground(palette().windowText());
        break;
    case ModeOffsetNormal:
        format_range.format.setForeground(offset_normal_fg_);
        break;
    case ModeOffsetField:
        format_range.format.setForeground(offset_field_fg_);
        break;
    case ModeNonPrintable:
        format_range.format.setForeground(offset_normal_fg_);
        break;
    }
    fmt_list << format_range;
    return true;
}

bool HexDataSourceView::addHexFormatRange(QList<QTextLayout::FormatRange> &fmt_list, int mark_start, int mark_length, int tvb_offset, int max_tvb_pos, HexDataSourceView::HighlightMode mode)
{
    int mark_end = mark_start + mark_length - 1;
    if (mark_start < 0 || mark_length < 1) return false;
    if (mark_start > max_tvb_pos && mark_end < tvb_offset) return false;

    int chars_per_byte;
    switch (recent.gui_bytes_view) {
    case BYTES_HEX:
        chars_per_byte = 2;
        break;
    case BYTES_BITS:
        chars_per_byte = 8;
        break;
    case BYTES_DEC:
    case BYTES_OCT:
        chars_per_byte = 3;
        break;
    default:
        ws_assert_not_reached();
    }
    int chars_plus_pad = chars_per_byte + 1;
    int byte_start = qMax(tvb_offset, mark_start) - tvb_offset;
    int byte_end = qMin(max_tvb_pos, mark_end) - tvb_offset;
    int fmt_start = offsetChars() + 1 // offset + spacing
            + (byte_start / separator_interval_)
            + (byte_start * chars_plus_pad);
    int fmt_length = offsetChars() + 1 // offset + spacing
            + (byte_end / separator_interval_)
            + (byte_end * chars_plus_pad)
            + chars_per_byte
            - fmt_start;
    return addFormatRange(fmt_list, fmt_start, fmt_length, mode);
}

bool HexDataSourceView::addAsciiFormatRange(QList<QTextLayout::FormatRange> &fmt_list, int mark_start, int mark_length, int tvb_offset, int max_tvb_pos, HexDataSourceView::HighlightMode mode)
{
    int mark_end = mark_start + mark_length - 1;
    if (mark_start < 0 || mark_length < 1) return false;
    if (mark_start > max_tvb_pos && mark_end < tvb_offset) return false;

    int byte_start = qMax(tvb_offset, mark_start) - tvb_offset;
    int byte_end = qMin(max_tvb_pos, mark_end) - tvb_offset;
    int fmt_start = offsetChars() + DataPrinter::hexChars() + 3 // offset + hex + spacing
            + (byte_start / separator_interval_)
            + byte_start;
    int fmt_length = offsetChars() + DataPrinter::hexChars() + 3 // offset + hex + spacing
            + (byte_end / separator_interval_)
            + byte_end
            + 1 // Just one character.
            - fmt_start;
    return addFormatRange(fmt_list, fmt_start, fmt_length, mode);
}

void HexDataSourceView::scrollToByte(int byte)
{
    if (recent.gui_bytes_view == BYTES_UTF8_TEXT) {
        // For UTF-8 text mode, estimate bytes per line
        int estimated_bytes_per_line = 50;
        verticalScrollBar()->setValue(byte / estimated_bytes_per_line);
    } else {
        verticalScrollBar()->setValue(byte / row_width_);
    }
}

// Offset character width
int HexDataSourceView::offsetChars(bool include_pad)
{
    int padding = include_pad ? 2 : 0;
    if (! data_.isEmpty() && data_.size() > 0xffff) {
        return 8 + padding;
    }
    return 4 + padding;
}

// Offset pixel width
int HexDataSourceView::offsetPixels()
{
    if (show_offset_) {
        // One pad space before and after
        QString zeroes = QString(offsetChars(), '0');
        return stringWidth(zeroes);
    }
    return 0;
}

// Hex pixel width
int HexDataSourceView::hexPixels()
{
    if (show_hex_) {
        // One pad space before and after
        QString zeroes = QString(DataPrinter::hexChars() + 2, '0');
        return stringWidth(zeroes);
    }
    return 0;
}

int HexDataSourceView::asciiPixels()
{
    if (show_ascii_) {
        // Two pad spaces before, one after
        int ascii_chars = (row_width_ + ((row_width_ - 1) / separator_interval_));
        QString zeroes = QString(ascii_chars + 3, '0');
        return stringWidth(zeroes);
    }
    return 0;
}

int HexDataSourceView::totalPixels()
{
    if (recent.gui_bytes_view == BYTES_UTF8_TEXT) {
        // For UTF-8 text-only mode, use viewport width
        return viewport()->width();
    }
    return offsetPixels() + hexPixels() + asciiPixels();
}

void HexDataSourceView::copyBytes(bool)
{
    QAction* action = qobject_cast<QAction*>(sender());
    if (!action) {
        return;
    }

    int dump_type = action->data().toInt();

    if (dump_type <= DataPrinter::DP_MimeData) {
        DataPrinter printer;
        printer.toClipboard((DataPrinter::DumpType) dump_type, this);
    }
}

// We do chunky (per-character) scrolling because it makes some of the
// math easier. Should we do smooth scrolling?
void HexDataSourceView::updateScrollbars()
{
    const int length = static_cast<int>(data_.size());
    if (length > 0 && line_height_ > 0 && em_width_ > 0) {
        if (recent.gui_bytes_view == BYTES_UTF8_TEXT) {
            // For UTF-8 text mode, estimate lines based on average bytes per line
            // We estimate ~50 bytes per line on average (conservative estimate)
            int estimated_bytes_per_line = 50;
            int all_lines_height = length / estimated_bytes_per_line + ((length % estimated_bytes_per_line) ? 1 : 0) - viewport()->height() / line_height_;
            verticalScrollBar()->setRange(0, qMax(0, all_lines_height));
            // No horizontal scrolling in text-only mode
            horizontalScrollBar()->setRange(0, 0);
        } else {
            int all_lines_height = length / row_width_ + ((length % row_width_) ? 1 : 0) - viewport()->height() / line_height_;
            verticalScrollBar()->setRange(0, qMax(0, all_lines_height));
            horizontalScrollBar()->setRange(0, qMax(0, int((totalPixels() - viewport()->width()) / em_width_)));
        }
    }
}

int HexDataSourceView::byteOffsetAtPixel(QPoint pos)
{
    int byte;
    if (recent.gui_bytes_view == BYTES_UTF8_TEXT) {
        // For UTF-8 text mode, estimate bytes per line
        int estimated_bytes_per_line = 50;
        int row = verticalScrollBar()->value() + (pos.y() / line_height_);
        byte = row * estimated_bytes_per_line;
    } else {
        byte = (verticalScrollBar()->value() + (pos.y() / line_height_)) * row_width_;
    }
    
    int x = (horizontalScrollBar()->value() * em_width_) + pos.x();
    int col = x_pos_to_column_.value(x, -1);

    if (col < 0) {
        return -1;
    }

    byte += col;
    if (byte > data_.size()) {
        return -1;
    }
    return byte;
}

void HexDataSourceView::setHexDisplayFormat(QAction *action)
{
    if (!action) {
        return;
    }

    recent.gui_bytes_view = action->data().value<bytes_view_type>();

    emit byteViewSettingsChanged();
}

void HexDataSourceView::setCharacterEncoding(QAction *action)
{
    if (!action) {
        return;
    }

    recent.gui_bytes_encoding = action->data().value<bytes_encoding_type>();

    emit byteViewSettingsChanged();
}
