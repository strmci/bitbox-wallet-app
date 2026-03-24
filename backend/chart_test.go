// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrimLeadingZeroes(t *testing.T) {
	t.Run("trims leading zeroes and keeps the first zero", func(t *testing.T) {
		result := trimLeadingZeroes([]ChartEntry{
			{Time: 1, Value: 0},
			{Time: 2, Value: 0},
			{Time: 3, Value: 5},
			{Time: 4, Value: 10},
		}, false)

		require.Equal(t, []ChartEntry{
			{Time: 2, Value: 0},
			{Time: 3, Value: 5},
			{Time: 4, Value: 10},
		}, result)
	})

	t.Run("keeps historical all-zero series", func(t *testing.T) {
		result := trimLeadingZeroes([]ChartEntry{
			{Time: 1, Value: 0},
			{Time: 2, Value: 0},
			{Time: 3, Value: 0},
		}, true)

		require.Equal(t, []ChartEntry{
			{Time: 1, Value: 0},
			{Time: 2, Value: 0},
			{Time: 3, Value: 0},
		}, result)
	})

	t.Run("drops synthetic zero-only series for empty wallets", func(t *testing.T) {
		result := trimLeadingZeroes([]ChartEntry{
			{Time: 1, Value: 0},
		}, false)

		require.Empty(t, result)
	})
}
