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
            // 1) App-provided supplier wins
            if (supplier != null) {
                Frame f = safeGet(supplier);
                if (isUsable(f))
                    return Optional.of(f);
            }

            // 2) Active or focused Frame
            KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
            Window w = kfm.getActiveWindow();
            if (!(w instanceof Frame))
                w = kfm.getFocusedWindow();
            if (w instanceof Frame && isUsable((Frame) w))
                return Optional.of((Frame) w);

            // 3) Any showing Frame, prefer front-most by a simple heuristic
            Optional<Frame> anyShowing = Arrays.stream(Frame.getFrames())
                    .filter(FrameFinder::isUsable)
                    .min(Comparator.comparingInt(FrameFinder::zOrderHint));
            if (anyShowing.isPresent())
                return anyShowing;
        } catch (SecurityException ignored) {
            // Sandbox environments may restrict this — fall through to empty
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

    private static boolean isUsable(Frame f) {
        return f != null && f.isShowing();
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
