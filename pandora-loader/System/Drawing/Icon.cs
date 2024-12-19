
namespace System.Drawing
{
    internal class Icon
    {
        private string iconPath;

        public Icon(string iconPath)
        {
            this.iconPath = iconPath;
        }

        public IntPtr Handle { get; internal set; }
    }
}