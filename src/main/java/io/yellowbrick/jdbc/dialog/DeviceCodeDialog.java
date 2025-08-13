/*
 * MIT License
 *
 * (c) 2025 Yellowbrick Data, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package io.yellowbrick.jdbc.dialog;

import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.net.URI;
import java.util.Timer;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Device code flow dialog using AWT
 */
public final class DeviceCodeDialog {
    private DeviceCodeDialog() {
    }

    public static Runnable show(String deviceAuthUrl, String deviceAuthCode, Consumer<Boolean> result) {

        // Set result once.
        AtomicBoolean resultReturned = new AtomicBoolean();
        Consumer<Boolean> returnResult = (Boolean dialogResult) -> {
            if (resultReturned.compareAndSet(false, true)) {
                result.accept(dialogResult);
            }
        };

        // Modeless dialog
        Frame parent = FrameFinder.findTopLevelFrame().orElse(null);
        Dialog dlg = new Dialog(parent, "Sign In", false);
        dlg.setBackground(new Color(0xFFFFFF));
        dlg.setLayout(new GridBagLayout());
        dlg.setResizable(false);
        AtomicBoolean disposed = new AtomicBoolean();
        Runnable dispose = () -> {
            if (disposed.compareAndSet(false, true)) {
                dlg.dispose();
            }
        };

        // Main panel
        Panel mainPanel = new Panel();
        mainPanel.setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.anchor = GridBagConstraints.WEST;

        // Header row: title
        c.insets = new Insets(50, 50, 20, 50);
        Panel headerPanel = new Panel(new GridBagLayout());
        Label title = new Label("Authenticate With Yellowbrick");
        title.setFont(new Font("SansSerif", Font.BOLD, 20));
        headerPanel.add(new LogoPanel(),
                new GridBagConstraints(0, 0, 0, 0, 0, 1, GridBagConstraints.WEST, 0, new Insets(0, 0, 0, 0), 0, 0));
        headerPanel.add(title,
                new GridBagConstraints(1, 0, 0, 0, 0, 1, GridBagConstraints.WEST, 0, new Insets(0, 80, 0, 0), 0, 0));
        mainPanel.add(headerPanel, c);

        // Instruction line: prefix + clickable link + suffix
        c.gridy++;
        c.insets = new Insets(4, 40, 6, 22);
        Panel instruct = new Panel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        Label pre = new Label("Visit");
        pre.setFont(new Font("SansSerif", Font.PLAIN, 13));
        pre.setForeground(new Color(0x2B2B2B));
        instruct.add(pre);

        LinkLabel link = new LinkLabel(deviceAuthUrl);
        link.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                openUrl(deviceAuthUrl);
            }
        });
        instruct.add(link);

        Label post = new Label("and enter the code:");
        post.setFont(new Font("SansSerif", Font.PLAIN, 13));
        post.setForeground(new Color(0x2B2B2B));
        instruct.add(post);

        mainPanel.add(instruct, c);

        TextField codeField = new TextField(deviceAuthCode, deviceAuthCode.length() + 1);
        codeField.setEditable(false);
        codeField.setFont(new Font("Monospaced", Font.BOLD, 24));
        codeField.setBackground(new Color(0xF5F7F6));
        codeField.setForeground(new Color(0x1E1E1E));

        ToastPanel toastPanel = new ToastPanel();
        MouseAdapter copyToClipboardListener = new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                try {
                    Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
                    cb.setContents(new StringSelection(deviceAuthCode), null);
                    toastPanel.showToast("Copied!");
                } catch (Exception ignored) {
                }
            }
        };
        toastPanel.addMouseListener(copyToClipboardListener);

        ClipboardButton copyBtn = new ClipboardButton("Copy");
        copyBtn.addMouseListener(copyToClipboardListener);

        Button loginBtn = new Button("Login");
        loginBtn.setPreferredSize(new Dimension(100, 38));
        loginBtn.addActionListener(e -> {
            openUrl(deviceAuthUrl);
        });

        Panel codeSpacer = new Panel();
        codeSpacer.setPreferredSize(new Dimension(16, 16));

        Panel codePanel = new Panel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        codePanel.addMouseListener(copyToClipboardListener);
        codePanel.setBackground(new Color(0xF5F7F6));
        codePanel.add(codeField);
        codePanel.add(copyBtn);

        // Code row: read-only field + small copy icon button + Login button
        c.gridy++;
        c.insets = new Insets(18, 22, 2, 22);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;
        Panel codeRow = new Panel(new FlowLayout(FlowLayout.CENTER, 0, 0));
        codeRow.add(codePanel);
        codeRow.add(codeSpacer);
        codeRow.add(loginBtn);
        mainPanel.add(codeRow, c);

        c.gridy++;
        c.insets = new Insets(0, 22, 0, 22);
        c.fill = GridBagConstraints.BOTH;
        c.weightx = 1.0;
        c.weighty = 1.0;
        mainPanel.add(toastPanel, c);

        // Footer row: Cancel (aligned right)
        c.gridy++;
        c.weighty = 0;
        c.anchor = GridBagConstraints.SOUTHEAST;
        c.insets = new Insets(0, 22, 0, 0);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;
        Panel footerPanel = new Panel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        Button cancel = new Button("Cancel");
        cancel.setPreferredSize(new Dimension(100, 38));
        cancel.addActionListener(e -> {
            returnResult.accept(false);
            dispose.run();
        });
        footerPanel.add(cancel);
        footerPanel.setPreferredSize(new Dimension(100, 40));
        mainPanel.add(footerPanel, c);

        // Keyboard: Enter = Login, Esc = Cancel
        KeyAdapter ka = new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
                    returnResult.accept(false);
                    dispose.run();
                }
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    openUrl(deviceAuthUrl);
                }
            }
        };
        for (Component comp : new Component[] { mainPanel, codeField, copyBtn, loginBtn, cancel, link }) {
            comp.addKeyListener(ka);
        }

        // Window close = Cancel
        dlg.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                returnResult.accept(false);
                dispose.run();
            }
        });

        // Layout
        GridBagConstraints outer = new GridBagConstraints();
        outer.gridx = 0;
        outer.gridy = 0;
        outer.anchor = GridBagConstraints.CENTER;
        outer.insets = new Insets(24, 24, 24, 24);
        outer.weightx = 1;
        outer.weighty = 1;
        outer.fill = GridBagConstraints.BOTH;
        dlg.add(mainPanel, outer);
        dlg.pack();

        // Nice default size
        Dimension sz = dlg.getSize();
        if (sz.width < 540)
            sz.width = 540;
        if (sz.height < 340)
            sz.height = 340;
        dlg.setSize(sz);
        dlg.setLocationRelativeTo(null);
        dlg.setVisible(true);

        // Attempt to bring to front
        EventQueue.invokeLater(() -> {
            dlg.setAlwaysOnTop(true);
            dlg.toFront();
            dlg.requestFocus();
            dlg.setAlwaysOnTop(false);
        });

        return () -> {
            dispose.run();
        };
    }

    // --- Helpers ----------------------------------------------------------------

    private static void openUrl(String url) {
        try {
            if (Desktop.isDesktopSupported())
                Desktop.getDesktop().browse(new URI(url));
        } catch (Exception ignored) {
        }
    }

    static final class LogoPanel extends Panel {
        private Image logo;

        LogoPanel() {
            this.logo = Toolkit.getDefaultToolkit().getImage(DeviceCodeDialog.class.getResource("yb_logo_80x80.png"));
            Dimension fixedSize = new Dimension(80, 80);
            this.setSize(fixedSize);
            this.setPreferredSize(fixedSize);
            this.setMinimumSize(fixedSize);
            this.setMaximumSize(fixedSize);
        }

        @Override
        public Dimension getPreferredSize() {
            return super.getPreferredSize();
        }

        @Override
        public Dimension getSize() {
            return super.getSize();
        }

        @Override
        public Dimension getMaximumSize() {
            return super.getMaximumSize();
        }

        @Override
        public Dimension getMinimumSize() {
            return super.getMinimumSize();
        }

        @Override
        public void paint(Graphics g) {
            super.paint(g);
            g.drawImage(this.logo, 0, 0, 80, 80, this);
        }
    }

    static final class ToastPanel extends Panel {
        private String toast;

        ToastPanel() {
        }

        @Override
        public void paint(Graphics g) {

            // toast
            if (toast != null) {
                Font smallFont = getFont().deriveFont(Font.PLAIN, 11f);
                g.setFont(smallFont);

                int w = getWidth();
                FontMetrics fm = g.getFontMetrics(getFont());
                int tw = fm.stringWidth(toast) + 12;
                int th = fm.getHeight() + 8;
                int x = (w - tw) / 2 - 6;
                int y = 6;

                // Toast background
                g.setColor(new Color(0, 0, 0, 180));
                g.fillRoundRect(x, y, tw, th, 10, 10);

                // Arrow (triangle) on top center of toast
                int arrowW = 10; // width of the arrow base
                int arrowH = 6; // height of the arrow
                int arrowX = x + tw / 2 - arrowW / 2;
                int arrowY = y - arrowH;

                int[] px = { arrowX, arrowX + arrowW, arrowX + arrowW / 2 };
                int[] py = { arrowY + arrowH, arrowY + arrowH, arrowY };
                g.fillPolygon(px, py, 3);

                // Toast text
                g.setColor(Color.white);
                g.drawString(toast, x + 10, y + th - fm.getDescent() - 4);
            }
        }

        void showToast(String text) {
            this.toast = text;
            new Timer(true).schedule(
                    new java.util.TimerTask() {
                        @Override
                        public void run() {
                            EventQueue.invokeLater(() -> {
                                ToastPanel.this.toast = null;
                                ToastPanel.this.repaint();
                            });
                        }
                    },
                    1400);
            repaint();
        }

        @Override
        public Dimension getPreferredSize() {
            return new Dimension(100, 80);
        }
    }

    static final class LinkLabel extends Label {
        LinkLabel(String text) {
            super(text);
            setForeground(new Color(0x86bc4d));
            setFont(new Font("SansSerif", Font.BOLD, 13));
            setCursor(new Cursor(Cursor.HAND_CURSOR));
        }

        @Override
        public void paint(Graphics g) {
            super.paint(g);
            FontMetrics fm = g.getFontMetrics();
            int y = getHeight() - fm.getDescent() + 1;
            g.drawLine(0, y, fm.stringWidth(getText()), y);
        }
    }

    /** Small square button with a drawn icon (copy). */
    static final class ClipboardButton extends Canvas {
        private final Image icon;

        ClipboardButton(String accessibilityName) {
            this.icon = Toolkit.getDefaultToolkit().getImage(DeviceCodeDialog.class.getResource("clipboard_24x24.png"));
            setName(accessibilityName);
            setCursor(new Cursor(Cursor.HAND_CURSOR));
            setSize(40, 40);
            setBackground(new Color(0xF5F7F6));
        }

        @Override
        public Dimension getPreferredSize() {
            return new Dimension(40, 40);
        }

        @Override
        public void paint(Graphics g) {
            g.drawImage(this.icon, 4, 8, 24, 24, this);
        }
    }

    // quick manual test
    public static void main(String[] args) {
        show("https://microsoft.com/devicelogin", "ALWD68P34", ok -> {
            System.out.println("Login pressed? " + ok);
            System.exit(0);
        });
    }
}
