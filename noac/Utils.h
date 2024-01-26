#pragma once

namespace Utils
{
    bool Contains(char* w1, char* w2, int max)
    {
        int i = 0;
        int j = 0;

        while (w1[i] != '\0' && i < max)
        {
            if (w1[i] == w2[j])
            {
                while (w1[i] == w2[j] && w2[j] != '\0')
                {
                    j++;
                    i++;
                }
                if (w2[j] == '\0')
                {
                    return true;
                }
                j = 0;
            }
            i++;
        }
        return false;
    }

    void ChangeMode(KPROCESSOR_MODE imode)
    {
        PUCHAR PrevMode = (PUCHAR)PsGetCurrentThread() + 0x232; // PrevMode from BlackBone
        *PrevMode = imode;
    }

    void SetDebugLevel(ULONG component, bool enable)
    {
        for (int i = 0; i < 12; i++)
        {
            DbgSetDebugFilterState(component, i, enable);
        }	
    }
}