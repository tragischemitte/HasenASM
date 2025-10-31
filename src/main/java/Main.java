import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public final class Main
{
    public static void main(final String[] args)
    {
        boolean decrypt;

        if (args[0].equals("d"))
        {
            decrypt = true;
        }
        else if (args[0].equals("e"))
        {
            decrypt = false;
        }
        else throw new IllegalArgumentException("Invalid argument: \"" + args[0] + "\", should be either \"d\" or \"e\"");

        try (final ZipInputStream zis = new ZipInputStream(new FileInputStream(args[1]));
             final ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(args[2])))
        {

            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null)
            {
                zos.putNextEntry(new ZipEntry(entry.getName()));

                if (entry.getName().endsWith(".class"))
                {
                    if (decrypt)
                    {
                        ClassReader.decrypt = true;
                    }
                    final ClassReader cr = new ClassReader(zis);

                    if (!decrypt)
                    {
                        ClassWriter.encrypt = true;
                    }
                    final ClassWriter cw = new ClassWriter(0);
                    cr.accept(cw, 0);

                    zos.write(cw.toByteArray());

                    System.out.println("Processed " + cr.getClassName());
                }
                else
                {
                    final byte[] buffer = new byte[1024];

                    int len;
                    while ((len = zis.read(buffer)) > 0)
                    {
                        zos.write(buffer, 0, len);
                    }
                }
                zos.closeEntry();
            }
        }
        catch (final Throwable t)
        {
            System.out.println("Error: " + t.getMessage());
            t.printStackTrace();
            System.out.println("Usage: java -jar converter.jar <e/d> *input file* *output file*");
        }
    }
}