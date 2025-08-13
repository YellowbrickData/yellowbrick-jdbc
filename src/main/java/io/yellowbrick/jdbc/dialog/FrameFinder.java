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
import java.util.Arrays;
import java.util.Comparator;
import java.util.Optional;
import java.util.function.Supplier;

import javax.swing.JFrame;

public final class FrameFinder {
    private FrameFinder() {
    }

    /**
     * Optional injection point: let the host app provide a preferred top-level
     * Frame.
     */
    private static volatile Supplier<Frame> supplier;

    /**
     * Set a supplier that returns the app's preferred top-level Frame (may return
     * null).
     * 
     * @param s supplier of top-level frame.
     */
    public static void setSupplier(Supplier<Frame> s) {
        supplier = s;
    }

    /**
     * Find the best top-level AWT Frame to use as a dialog owner.
     * 
     * @return top-level AWT frame for parenting a dialog.
     **/
    public static Optional<Frame> findTopLevelFrame() {
        try {
            // 1) App-provided
            if (supplier != null) {
                Frame f = safeGet(supplier);
                if (isUsable(f))
                    return Optional.of(f);
            }

            // 2) Active or focused Frame
            KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();

            Window w = kfm.getActiveWindow();
            if (w == null) {
                w = kfm.getFocusedWindow();
            }
            Frame owner = windowToFrame(w);
            if (isUsable(owner)) {
                return Optional.of(owner);
            }

            // 3) Prefer a visible, non-iconified Frame
            Optional<Frame> fr = Arrays.stream(Frame.getFrames())
                    .filter(FrameFinder::isVisibleNotIconified)
                    .min(Comparator.comparingInt(FrameFinder::zOrderHint));
            if (fr.isPresent()) {
                return fr;
            }

            // 4) As a last resort, scan all Windows and map to owner Frames
            for (Window win : Window.getWindows()) {
                Frame f = windowToFrame(win);
                if (isUsable(f)) {
                    return Optional.of(f);
                }
            }
        } catch (SecurityException ignored) {
        }
        return Optional.empty();
    }

    private static <T> T safeGet(Supplier<T> s) {
        try {
            return s.get();
        } catch (Throwable t) {
            return null;
        }
    }

    private static Frame windowToFrame(Window w) {
        while (w != null && !(w instanceof Frame)) {
            w = w.getOwner();
        }
        return (Frame) w;
    }

    private static boolean isUsable(Frame f) {
        return f != null && f.isDisplayable() && isVisibleNotIconified(f);
    }

    private static boolean isVisibleNotIconified(Frame f) {
        return f != null
                && f.isVisible()
                && (f.getExtendedState() & Frame.ICONIFIED) == 0;
    }

    /** Lower score ≈ more likely front-most. */
    private static int zOrderHint(Frame f) {
        int score = 0;
        if (f.isFocused())
            score -= 10;
        if (f.isActive())
            score -= 5;
        if (f.isAlwaysOnTop())
            score -= 3;
        Dimension d = f.getSize();
        // prefer larger "main" windows slightly
        int areaPenalty = 10_000_000 - Math.max(1, d.width * d.height);
        score += areaPenalty;
        return score;
    }
}
