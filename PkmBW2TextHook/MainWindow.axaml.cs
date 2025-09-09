using Avalonia.Controls;
using Avalonia.Threading;
using System;
using System.Threading;

namespace PkmBW2TextHook
{
    public partial class MainWindow : Window
    {
        private TextHook _textHook;


        public MainWindow()
        {
            InitializeComponent();

            _textHook = new TextHook();
            _textHook.OnTextExtracted += TextHook_OnTextExtracted;
            _textHook.OnLog += TextHook_OnLog;

            HookButton.Click += HookButton_Click;
            StartButton.Click += StartButton_Click;

        }

        private void HookButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            Thread hookThread = new Thread(() =>
            {
                _textHook.HookProcess();
            })
            { IsBackground = true };
            hookThread.Start();
        }

        private void StartButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            Thread startThread = new Thread(() =>
            {
                _textHook.StartExtracting();
            })
            { IsBackground = true };
            startThread.Start();
        }



        private void TextHook_OnTextExtracted(string text)
        {
            Dispatcher.UIThread.InvokeAsync(() =>
            {
                AppendLog("---- Extracted Text ----");
                AppendLog(text);

                if (AutoCopyCheckBox.IsChecked == true)
                {
                    _textHook.CopyToClipboard(text);
                }
            });
        }

        private void TextHook_OnLog(string message)
        {

            Dispatcher.UIThread.InvokeAsync(() =>
            {
                AppendLog(message);
            });
        }

        private void AppendLog(string message)
        {
            LogTextBox.Text += message + Environment.NewLine;
            LogTextBox.CaretIndex = LogTextBox.Text.Length;
        }
    }
}