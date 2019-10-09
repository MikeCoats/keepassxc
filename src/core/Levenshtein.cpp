/*
 *  Copyright (C) 2019 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "Levenshtein.h"

#include <QVector>

namespace Levenshtein
{
    /**
     * An implementation of the Levenshtein distance calculation.
     * 
     * The Wagner-Fischer algorithm is an approach to implement the calculation
     * of the Levenshtein distance. This implementation uses the naive, flood-
     * fill method. There is opportunity to move to a two-column approach to
     * save memory, or the 2k-1 diagonal stripe method to provide a pass/fail
     * to reduce run time.
     * 
     * @param source The string to calculate the Levenshtein distance from
     * @param target The string to calculate the Levenshtein distance to
     * @return The Levenshtein distance between the source and the target
     */
    unsigned int wagnerFischerMatrixMethod(QString source, QString target)
    {
        // Nudge the test strings along by one to 1-index them instead of 0-index
        // them, leaving the 0 position available for the start-scores.
        QString down = source.prepend(' ');
        QString across = target.prepend(' ');

        QVector<QVector<int>> score(down.length(), QVector<int>(across.length(), 0));

        for (int y = 0; y < down.length(); y++) {
            score[y][0] = y;
        }
        for (int x = 0; x < across.length(); x++) {
            score[0][x] = x;
        }

        for (int y = 1; y < down.length(); y++) {
            for (int x = 1; x < across.length(); x++) {
                score[y][x] = std::min(std::min(score[y][x - 1] + 1, score[y - 1][x] + 1),
                                       down.at(y) == across.at(x) ? score[y - 1][x - 1] : score[y - 1][x - 1] + 1);
            }
        }

        return score.last().last();
    }

    /**
     * Calculate the Levenshtein distance between two strings.
     * 
     * The Levenshtein distance between two strings is the number of characters
     * that must be added, removed or substituted to transform one string into
     * another. This is useful for checking if multiple, similar passwords are
     * in use. For example, "bad-password--2018-03" & "bad-password--2019-09"
     * have a Levenshtein distance of only 2 as there are only 2 substitutions.
     * Similarly, the passwords "bad-password" and "bad-password-2018" have a
     * Levenshtein distance of only 5. Comparing the distance of 5 to larger
     * password's length of 17 shows there is a lot of shared information
     * between these two strings.
     * 
     * @param source The string to calculate the Levenshtein distance from
     * @param target The string to calculate the Levenshtein distance to
     * @return The Levenshtein distance between the source and the target
     */
    unsigned int distance(QString source, QString target)
    {
        return wagnerFischerMatrixMethod(source, target);
    }
} // namespace Levenshtein
